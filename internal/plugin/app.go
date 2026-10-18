package plugin

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/musnows/cpa-plugin-llm-moderation/internal/moderation"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

//go:embed web/*
var webFiles embed.FS

const managementBase = "/v0/management/plugins/" + moderation.ID

type state struct {
	config          moderation.Config
	configError     error
	lastConfigError string
	store           *moderation.FileStore
}
type App struct {
	engine *moderation.Engine
	state  atomic.Pointer[state]
	ctx    context.Context
	cancel context.CancelFunc
	mu     sync.Mutex
	closed bool
	active sync.WaitGroup
}

func New(transport moderation.Transport, logger moderation.Logger) *App {
	ctx, cancel := context.WithCancel(context.Background())
	app := &App{engine: moderation.NewEngine(transport, logger), ctx: ctx, cancel: cancel}
	cfg := moderation.DefaultConfig()
	app.state.Store(&state{config: cfg, configError: errors.New("configuration_required"), store: moderation.NewFileStore(cfg.LogDir)})
	return app
}

func (a *App) Close() {
	a.mu.Lock()
	a.closed = true
	a.cancel()
	a.mu.Unlock()
	a.active.Wait()
}

func (a *App) Handle(method string, raw []byte) (result any, err error) {
	if method == "plugin.quiesce" || method == "plugin.shutdown" {
		a.Close()
		return struct{}{}, nil
	}
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		if method == "request.intercept_before" {
			return failClosed(), nil
		}
		return nil, errors.New("plugin_is_stopping")
	}
	a.active.Add(1)
	a.mu.Unlock()
	defer a.active.Done()
	defer func() {
		if recover() != nil {
			if method == "request.intercept_before" {
				result, err = failClosed(), nil
			} else {
				result, err = nil, errors.New("plugin_internal_error")
			}
		}
	}()
	switch method {
	case "plugin.register", "plugin.reconfigure":
		var request struct {
			ConfigYAML []byte `json:"config_yaml"`
		}
		if json.Unmarshal(raw, &request) != nil {
			return nil, errors.New("invalid_lifecycle_request")
		}
		cfg, configErr := moderation.ParseConfig(request.ConfigYAML)
		if method == "plugin.reconfigure" && configErr != nil {
			previous := *a.state.Load()
			previous.lastConfigError = configErr.Error()
			a.state.Store(&previous)
			if a.engine.Logger != nil {
				a.engine.Logger.Log("", "warn", "configuration_update_rejected", map[string]any{"error_code": configErr.Error()})
			}
			// Keep the capability registered: CPA drops interceptors whose reconfigure RPC fails.
			return registration(), nil
		}
		if configErr != nil {
			cfg.FailurePolicy, cfg.Threshold, cfg.Enabled = "deny", 80, true
			if cfg.LogDir == "" {
				cfg.LogDir = moderation.DefaultConfig().LogDir
			}
		}
		a.state.Store(&state{config: cfg, configError: configErr, store: moderation.NewFileStore(cfg.LogDir)})
		return registration(), nil
	case "request.intercept_before":
		var request struct {
			pluginapi.RequestInterceptRequest
			CallbackID string `json:"host_callback_id"`
		}
		if json.Unmarshal(raw, &request) != nil {
			return failClosed(), nil
		}
		s := a.state.Load()
		return a.engine.Intercept(a.ctx, request.CallbackID, request.RequestInterceptRequest, s.config, s.configError, s.store), nil
	case "request.intercept_after":
		return pluginapi.RequestInterceptResponse{}, nil
	case "management.register":
		var routes []map[string]string
		for _, route := range []struct{ method, path string }{{"GET", "health"}, {"GET", "models"}, {"POST", "models"}, {"GET", "records"}, {"GET", "summary"}, {"POST", "test"}, {"POST", "validate"}} {
			routes = append(routes, map[string]string{"Method": route.method, "Path": managementBase + "/" + route.path})
		}
		return map[string]any{"routes": routes, "resources": []map[string]string{{"Path": "/dashboard", "Menu": "LLM 输入预检", "Description": "Input moderation configuration and audit logs."}, {"Path": "/app.js"}, {"Path": "/style.css"}}}, nil
	case "management.handle":
		var request struct {
			pluginapi.ManagementRequest
			CallbackID string `json:"host_callback_id"`
		}
		if json.Unmarshal(raw, &request) != nil {
			return nil, errors.New("invalid_management_request")
		}
		return a.management(request.ManagementRequest, request.CallbackID), nil
	default:
		return nil, errors.New("unsupported_plugin_method")
	}
}

func failClosed() pluginapi.RequestInterceptResponse {
	return pluginapi.RequestInterceptResponse{Terminate: true, StatusCode: 503, ResponseHeaders: http.Header{"Content-Type": {"application/json"}}, ResponseBody: []byte(`{"error":{"code":"moderation_unavailable","message":"Input moderation is temporarily unavailable.","type":"moderation_error"}}`)}
}

func FailureResponse() pluginapi.RequestInterceptResponse { return failClosed() }

func jsonResponse(status int, value any) pluginapi.ManagementResponse {
	body, _ := json.Marshal(value)
	return pluginapi.ManagementResponse{StatusCode: status, Headers: http.Header{"Content-Type": {"application/json"}, "Cache-Control": {"no-store"}}, Body: body}
}
func errorResponse(status int, code string) pluginapi.ManagementResponse {
	return jsonResponse(status, map[string]string{"error": code})
}

func (a *App) management(req pluginapi.ManagementRequest, callbackID string) pluginapi.ManagementResponse {
	if strings.HasPrefix(req.Path, "/v0/resource/plugins/"+moderation.ID+"/") {
		name, contentType := "index.html", "text/html; charset=utf-8"
		switch {
		case strings.HasSuffix(req.Path, "/app.js"):
			name, contentType = "app.js", "text/javascript; charset=utf-8"
		case strings.HasSuffix(req.Path, "/style.css"):
			name, contentType = "style.css", "text/css; charset=utf-8"
		case strings.HasSuffix(req.Path, "/dashboard"):
		default:
			return errorResponse(404, "not_found")
		}
		body, err := webFiles.ReadFile("web/" + name)
		if err != nil {
			return errorResponse(500, "resource_unavailable")
		}
		return pluginapi.ManagementResponse{StatusCode: 200, Headers: http.Header{"Content-Type": {contentType}, "Cache-Control": {"no-store"}, "X-Content-Type-Options": {"nosniff"}, "Referrer-Policy": {"no-referrer"}}, Body: body}
	}
	s := a.state.Load()
	path := strings.TrimPrefix(req.Path, managementBase+"/")
	switch path {
	case "health":
		message := ""
		if s.configError != nil {
			message = s.configError.Error()
		}
		active := s.config
		active.CPAAPIKey, active.PrimaryAPIKey, active.FallbackAPIKey = "", "", ""
		return jsonResponse(200, map[string]any{"ready": s.configError == nil, "config_error": message, "last_config_error": s.lastConfigError, "version": moderation.Version, "prompt_version": moderation.PromptVersion, "required_response_steering": false, "active_config": active})
	case "validate":
		_, err := moderation.ParseConfig(req.Body)
		if err != nil {
			return errorResponse(400, err.Error())
		}
		return jsonResponse(200, map[string]bool{"valid": true})
	case "models":
		cfg := s.config
		if req.Method == "POST" {
			var fields map[string]json.RawMessage
			if moderation.DecodeJSON(req.Body, &fields) != nil {
				return errorResponse(400, "invalid_configuration")
			}
			cfg, _ = moderation.ParseConfig(req.Body)
		}
		probe := cfg
		probe.Enabled, probe.Threshold, probe.PrimaryMode, probe.PrimaryModel, probe.FallbackEnabled = true, 80, "cpa", "model-list-probe", false
		if err := probe.Validate(); err != nil {
			return errorResponse(400, err.Error())
		}
		ctx, cancel := context.WithTimeout(a.ctx, cfg.Primary().Timeout)
		defer cancel()
		resp, err := a.engine.Transport.Do(ctx, callbackID, moderation.HTTPRequest{Method: "GET", URL: cfg.CPAURL("models"), Headers: http.Header{"Authorization": {"Bearer " + cfg.CPAAPIKey}}})
		if err != nil || resp.StatusCode != 200 {
			return errorResponse(502, "model_list_unavailable")
		}
		var catalog struct {
			Data []struct {
				ID      string `json:"id"`
				OwnedBy string `json:"owned_by"`
			} `json:"data"`
		}
		if len(resp.Body) > moderation.MaxResponseBytes || moderation.DecodeJSON(resp.Body, &catalog) != nil {
			return errorResponse(502, "invalid_model_list")
		}
		sort.Slice(catalog.Data, func(i, j int) bool { return catalog.Data[i].ID < catalog.Data[j].ID })
		if catalog.Data == nil {
			catalog.Data = []struct {
				ID      string `json:"id"`
				OwnedBy string `json:"owned_by"`
			}{}
		}
		return jsonResponse(200, map[string]any{"models": catalog.Data})
	case "test":
		var input struct {
			Target string          `json:"target"`
			Config json.RawMessage `json:"config"`
		}
		if moderation.DecodeJSON(req.Body, &input) != nil || (input.Target != "primary" && input.Target != "fallback") {
			return errorResponse(400, "invalid_test_request")
		}
		cfg := s.config
		if len(input.Config) > 0 {
			var err error
			cfg, err = moderation.ParseConfig(input.Config)
			if err != nil {
				return errorResponse(400, err.Error())
			}
		}
		reviewer := cfg.Primary()
		if input.Target == "fallback" {
			if !cfg.FallbackEnabled {
				return errorResponse(400, "fallback_disabled")
			}
			reviewer = cfg.Fallback()
		}
		if reviewer.Endpoint == "" || reviewer.Model == "" || reviewer.Timeout <= 0 {
			return errorResponse(400, "reviewer_configuration_required")
		}
		verdict, attempt, err := a.engine.Review(a.ctx, callbackID, reviewer, []string{"Please write a short poem about a quiet garden."})
		if err != nil {
			return jsonResponse(200, map[string]any{"success": false, "attempt": attempt})
		}
		return jsonResponse(200, map[string]any{"success": true, "attempt": attempt, "verdict": verdict})
	case "records", "summary":
		filter, err := parseFilter(req)
		if err != nil {
			return errorResponse(400, err.Error())
		}
		if path == "records" {
			page, err := s.store.Records(filter)
			if err != nil {
				return errorResponse(500, err.Error())
			}
			return jsonResponse(200, page)
		}
		summary, err := s.store.Summary(filter)
		if err != nil {
			return errorResponse(500, err.Error())
		}
		return jsonResponse(200, summary)
	default:
		return errorResponse(404, "not_found")
	}
}

func parseFilter(req pluginapi.ManagementRequest) (moderation.Filter, error) {
	now := time.Now().UTC()
	f := moderation.Filter{From: now.Add(-24 * time.Hour), To: now, Key: req.Query.Get("key"), TargetModel: req.Query.Get("target_model"), ReviewModel: req.Query.Get("review_model"), Decision: req.Query.Get("decision"), Cursor: req.Query.Get("cursor"), Limit: 50}
	for _, pair := range []struct {
		name   string
		target *time.Time
	}{{"from", &f.From}, {"to", &f.To}} {
		if value := req.Query.Get(pair.name); value != "" {
			parsed, err := time.Parse(time.RFC3339Nano, value)
			if err != nil {
				return f, errors.New("invalid_time_range")
			}
			*pair.target = parsed
		}
	}
	if f.To.Before(f.From) || f.To.Sub(f.From) > 31*24*time.Hour {
		return f, errors.New("time_range_must_be_between_zero_and_31_days")
	}
	if raw := req.Query.Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > 200 {
			return f, errors.New("limit_must_be_between_1_and_200")
		}
		f.Limit = n
	}
	return f, nil
}

func registration() any {
	fields := []pluginapi.ConfigField{
		{Name: "primary_mode", Type: pluginapi.ConfigFieldTypeEnum, EnumValues: []string{"cpa", "external"}, Default: "cpa", Description: "Primary reviewer connection mode."},
		{Name: "cpa_base_url", Type: pluginapi.ConfigFieldTypeString, Description: "CPA internal HTTP base URL, optionally ending in /v1."},
		{Name: "cpa_api_key", Type: pluginapi.ConfigFieldTypeString, Description: "CPA key used only for internal reviewer requests."},
		{Name: "primary_endpoint", Type: pluginapi.ConfigFieldTypeString, Description: "Full external Chat Completions endpoint."},
		{Name: "primary_api_key", Type: pluginapi.ConfigFieldTypeString, Description: "External reviewer API key."},
		{Name: "primary_model", Type: pluginapi.ConfigFieldTypeString, Description: "Primary reviewer model ID."},
		{Name: "primary_timeout", Type: pluginapi.ConfigFieldTypeString, Default: "10s", Description: "Primary request timeout."},
		{Name: "fallback_enabled", Type: pluginapi.ConfigFieldTypeBoolean, Default: false, Description: "Enable the independent fallback reviewer."},
		{Name: "fallback_endpoint", Type: pluginapi.ConfigFieldTypeString, Description: "Full fallback Chat Completions endpoint."},
		{Name: "fallback_api_key", Type: pluginapi.ConfigFieldTypeString, Description: "Fallback reviewer API key."},
		{Name: "fallback_model", Type: pluginapi.ConfigFieldTypeString, Description: "Fallback reviewer model ID."},
		{Name: "fallback_timeout", Type: pluginapi.ConfigFieldTypeString, Default: "10s", Description: "Fallback request timeout."},
		{Name: "threshold", Type: pluginapi.ConfigFieldTypeNumber, Default: 80, Description: "Block only when confidence is strictly greater. Zero blocks all; 100 never blocks by score."},
		{Name: "failure_policy", Type: pluginapi.ConfigFieldTypeEnum, EnumValues: []string{"deny", "allow"}, Default: "deny", Description: "Action when both reviewers fail."},
		{Name: "log_dir", Type: pluginapi.ConfigFieldTypeString, Default: "./logs/llm-moderation", Description: "Daily JSONL directory relative to the CPA working directory."},
	}
	return map[string]any{"schema_version": 6, "metadata": pluginapi.Metadata{Name: moderation.ID, Version: moderation.Version, Author: "musnows", GitHubRepository: "https://github.com/musnows/cpa-plugin-llm-moderation", ConfigFields: fields}, "capabilities": map[string]bool{"request_interceptor": true, "management_api": true}}
}
