package moderation

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

type HTTPRequest struct {
	Method  string      `json:"method"`
	URL     string      `json:"url"`
	Headers http.Header `json:"headers"`
	Body    []byte      `json:"body"`
}
type HTTPResponse struct {
	StatusCode int
	Headers    http.Header
	Body       []byte
}
type Transport interface {
	Do(context.Context, string, HTTPRequest) (HTTPResponse, error)
}
type Logger interface {
	Log(string, string, string, map[string]any)
}

type Engine struct {
	Transport Transport
	Nonces    *Nonces
	Logger    Logger
}

func NewEngine(t Transport, logger Logger) *Engine {
	return &Engine{Transport: t, Nonces: NewNonces(), Logger: logger}
}

func ms(start time.Time) float64 { return float64(time.Since(start)) / float64(time.Millisecond) }

func (e *Engine) Review(ctx context.Context, callbackID string, reviewer Reviewer, texts []string) (Verdict, Attempt, error) {
	start := time.Now()
	a := Attempt{Reviewer: reviewer.Name, Model: reviewer.Model, Outcome: "error"}
	data, _ := json.Marshal(map[string]any{"user_messages": texts})
	body, err := json.Marshal(map[string]any{
		"model": reviewer.Model, "stream": false,
		"messages": []map[string]string{{"role": "system", "content": SystemPrompt}, {"role": "user", "content": string(data)}},
	})
	if err != nil {
		a.ErrorCode = "review_request_encoding_failed"
		return Verdict{}, a, err
	}
	token, err := e.Nonces.Issue(body, reviewer.APIKey, reviewer.Timeout+time.Minute)
	if err != nil {
		a.ErrorCode = "review_concurrency_limit"
		a.DurationMS = ms(start)
		return Verdict{}, a, err
	}
	defer e.Nonces.Forget(token)
	headers := http.Header{"Content-Type": {"application/json"}, InternalHeader: {token}}
	if reviewer.APIKey != "" {
		headers.Set("Authorization", "Bearer "+reviewer.APIKey)
	}
	callCtx, cancel := context.WithTimeout(ctx, reviewer.Timeout)
	defer cancel()
	resp, err := e.Transport.Do(callCtx, callbackID, HTTPRequest{Method: http.MethodPost, URL: reviewer.Endpoint, Headers: headers, Body: body})
	a.DurationMS = ms(start)
	a.HTTPStatus = resp.StatusCode
	if err != nil {
		switch {
		case errors.Is(err, context.Canceled):
			a.ErrorCode = "review_canceled"
		case errors.Is(err, context.DeadlineExceeded):
			a.ErrorCode = "review_timeout"
		default:
			a.ErrorCode = "review_transport_error"
		}
		return Verdict{}, a, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		a.ErrorCode = "review_http_error"
		return Verdict{}, a, errors.New(a.ErrorCode)
	}
	v, err := ParseCompletion(resp.Body)
	if err != nil {
		a.ErrorCode = err.Error()
		return Verdict{}, a, err
	}
	a.Outcome = "success"
	return v, a, nil
}

func termination(status int, code string, id string) pluginapi.RequestInterceptResponse {
	message := "Request blocked by input moderation."
	if status != http.StatusForbidden {
		message = "Input moderation is temporarily unavailable."
	}
	body, _ := json.Marshal(map[string]any{"error": map[string]any{"type": "moderation_error", "code": code, "message": message}, "request_id": id})
	return pluginapi.RequestInterceptResponse{Terminate: true, StatusCode: status, ResponseHeaders: http.Header{"Content-Type": {"application/json"}}, ResponseBody: body}
}

func (e *Engine) Intercept(ctx context.Context, callbackID string, req pluginapi.RequestInterceptRequest, cfg Config, configError error, sink Sink) (response pluginapi.RequestInterceptResponse) {
	start := time.Now()
	if e.Nonces.Consume(req.Headers.Get(InternalHeader), req.Body, req.Metadata) {
		return pluginapi.RequestInterceptResponse{ClearHeaders: []string{InternalHeader}}
	}
	if !cfg.Enabled {
		return pluginapi.RequestInterceptResponse{ClearHeaders: []string{InternalHeader}}
	}
	key, masked := Identify(req.Headers, req.Metadata)
	r := Record{Time: start.UTC(), RequestID: req.RequestID, TraceID: req.TraceID, Protocol: req.SourceFormat, TargetModel: req.Model,
		RequestedModel: req.RequestedModel, KeyFingerprint: key, MaskedKey: masked, Threshold: cfg.Threshold,
		Categories: []string{}, Attempts: []Attempt{}, PromptVersion: PromptVersion}
	secrets := append(cfg.Secrets(), HeaderKeys(req.Headers)...)
	var texts []string
	defer func() {
		if recover() != nil {
			r.Decision, r.ErrorCode, r.Reason = "error_denied", "moderation_internal_error", "Input moderation encountered an internal error."
			response = termination(503, "moderation_unavailable", req.RequestID)
		}
		r.PrecheckDurationMS = ms(start)
		if response.Terminate {
			r.DecisionStatus = response.StatusCode
			if r.ErrorCode == "" && response.StatusCode == 403 {
				r.ErrorCode = "content_policy_violation"
			}
		}
		r.Reason = redact(r.Reason, secrets)
		for _, text := range texts {
			if len(text) >= 4 {
				r.Reason = strings.ReplaceAll(r.Reason, text, "[redacted user text]")
			}
		}
		if sink != nil {
			if err := sink.Append(r); err != nil && e.Logger != nil {
				e.Logger.Log(callbackID, "error", "audit_log_write_failed", map[string]any{"record": r, "error_code": err.Error()})
			}
		}
		response.ClearHeaders = append(response.ClearHeaders, InternalHeader)
	}()
	fail := func(code string, canceled bool) pluginapi.RequestInterceptResponse {
		r.ErrorCode, r.Reason = code, "Input moderation could not produce a valid verdict."
		if canceled {
			r.Decision = "canceled"
			return termination(503, "moderation_unavailable", req.RequestID)
		}
		if cfg.FailurePolicy == "allow" {
			r.Decision = "error_allowed"
			return pluginapi.RequestInterceptResponse{}
		}
		r.Decision = "error_denied"
		return termination(503, "moderation_unavailable", req.RequestID)
	}
	if cfg.Threshold == 0 {
		r.Decision, r.Reason = "block", "All requests are blocked by threshold zero."
		return termination(403, "content_policy_violation", req.RequestID)
	}
	if configError != nil {
		return fail("invalid_configuration", false)
	}
	var err error
	texts, err = ExtractUserTexts(req.SourceFormat, req.Body)
	if errors.Is(err, ErrUnsupported) {
		r.Decision, r.Reason = "skipped", "Unsupported protocol."
		return response
	}
	if err != nil {
		return fail(err.Error(), false)
	}
	if len(texts) == 0 {
		r.Decision, r.Reason = "skipped", "No visible user text."
		r.ErrorCode = "skipped_no_user_text"
		return response
	}
	if ctx.Err() != nil {
		return fail("request_canceled", true)
	}
	reviewStart := time.Now()
	v, attempt, err := e.Review(ctx, callbackID, cfg.Primary(), texts)
	r.Attempts = append(r.Attempts, attempt)
	r.PrimaryDurationMS = attempt.DurationMS
	if err != nil && !errors.Is(err, context.Canceled) && ctx.Err() == nil && cfg.FallbackEnabled {
		r.FallbackUsed = true
		v, attempt, err = e.Review(ctx, callbackID, cfg.Fallback(), texts)
		r.Attempts = append(r.Attempts, attempt)
		r.FallbackDurationMS = attempt.DurationMS
	}
	r.ReviewTotalMS = ms(reviewStart)
	if err != nil {
		return fail(attempt.ErrorCode, errors.Is(err, context.Canceled) || ctx.Err() != nil)
	}
	r.FinalReviewer, r.FinalReviewModel = attempt.Reviewer, attempt.Model
	r.IsViolation, r.Confidence, r.Categories, r.Reason = &v.IsViolation, &v.Confidence, v.Categories, v.Reason
	if v.IsViolation && v.Confidence > cfg.Threshold {
		r.Decision = "block"
		return termination(403, "content_policy_violation", req.RequestID)
	}
	r.Decision = "allow"
	return response
}
