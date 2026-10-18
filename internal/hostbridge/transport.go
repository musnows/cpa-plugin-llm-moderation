package hostbridge

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/musnows/cpa-plugin-llm-moderation/internal/moderation"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

type Caller func(string, any, any) error

type Transport struct{ Call Caller }

func (t *Transport) Do(ctx context.Context, callbackID string, request moderation.HTTPRequest) (moderation.HTTPResponse, error) {
	if ctx.Err() != nil {
		return moderation.HTTPResponse{}, ctx.Err()
	}
	var operation struct {
		ID string `json:"operation_id"`
	}
	if err := t.Call("host.http.operation_open", map[string]any{"host_callback_id": callbackID}, &operation); err != nil {
		return moderation.HTTPResponse{}, classify(err)
	}
	if operation.ID == "" {
		return moderation.HTTPResponse{}, errors.New("missing_host_operation_id")
	}
	cancel := func() {
		_ = t.Call("host.http.cancel", map[string]any{"host_callback_id": callbackID, "operation_id": operation.ID}, nil)
	}
	defer cancel()
	type result struct {
		response pluginapi.HTTPResponse
		err      error
	}
	done := make(chan result, 1)
	go func() {
		var outcome result
		defer func() {
			if recover() != nil {
				outcome.err = errors.New("host_http_panic")
			}
			done <- outcome
		}()
		outcome.err = t.Call("host.http.do", map[string]any{
			"host_callback_id": callbackID, "operation_id": operation.ID,
			"method": request.Method, "url": request.URL, "headers": request.Headers, "body": request.Body,
		}, &outcome.response)
	}()
	select {
	case r := <-done:
		if ctx.Err() != nil {
			return moderation.HTTPResponse{}, ctx.Err()
		}
		return moderation.HTTPResponse{StatusCode: r.response.StatusCode, Headers: r.response.Headers, Body: r.response.Body}, classify(r.err)
	case <-ctx.Done():
		cancel()
		// Join the host call before returning; fallback must not leave the primary running.
		<-done
		return moderation.HTTPResponse{}, ctx.Err()
	}
}

func classify(err error) error {
	if err == nil {
		return nil
	}
	text := strings.ToLower(err.Error())
	if strings.Contains(text, "context canceled") || strings.Contains(text, "context cancelled") {
		return context.Canceled
	}
	if strings.Contains(text, "deadline exceeded") {
		return context.DeadlineExceeded
	}
	return errors.New("host_http_failed")
}

func (t *Transport) Log(callbackID, level, message string, fields map[string]any) {
	_ = t.Call("host.log", map[string]any{"host_callback_id": callbackID, "level": level, "message": message, "fields": fields}, nil)
}

func DecodeEnvelope(raw []byte, dst any) error {
	var envelope struct {
		OK     bool            `json:"ok"`
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if json.Unmarshal(raw, &envelope) != nil {
		return errors.New("invalid_host_envelope")
	}
	if !envelope.OK {
		if envelope.Error != nil {
			return errors.New(envelope.Error.Message)
		}
		return errors.New("host_callback_failed")
	}
	if dst == nil {
		return nil
	}
	return json.Unmarshal(envelope.Result, dst)
}
