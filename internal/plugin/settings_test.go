package plugin

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/musnows/cpa-plugin-llm-moderation/internal/moderation"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

type captureTransport struct {
	requests  []moderation.HTTPRequest
	deadlines []time.Duration
	response  []byte
}

func (c *captureTransport) Do(ctx context.Context, _ string, request moderation.HTTPRequest) (moderation.HTTPResponse, error) {
	c.requests = append(c.requests, request)
	deadline, _ := ctx.Deadline()
	c.deadlines = append(c.deadlines, time.Until(deadline))
	return moderation.HTTPResponse{StatusCode: 200, Body: c.response}, nil
}

func reviewerConfig() moderation.Config {
	cfg := moderation.DefaultConfig()
	cfg.PrimaryModel = "primary-model"
	cfg.CPABaseURL, cfg.CPAAPIKey = "http://127.0.0.1:18101", "primary-cpa-secret"
	cfg.FallbackEnabled, cfg.FallbackMode = true, "cpa"
	cfg.FallbackCPAURL, cfg.FallbackCPAKey = "http://127.0.0.1:18102/v1", "fallback-cpa-secret"
	cfg.FallbackModel, cfg.FallbackTimeout = "fallback-model", 600
	return cfg
}

func TestModelListsUseSelectedReviewerConnection(t *testing.T) {
	for _, target := range []string{"primary", "fallback"} {
		transport := &captureTransport{response: []byte(`{"data":[{"id":"selected-model"}]}`)}
		app := New(transport, nil)
		cfg := reviewerConfig()
		body, _ := json.Marshal(cfg)
		response := app.management(pluginapi.ManagementRequest{Method: "POST", Path: managementBase + "/models", Query: url.Values{"target": {target}}, Body: body}, "scope")
		if response.StatusCode != 200 || len(transport.requests) != 1 {
			t.Fatalf("model list failed: %s", response.Body)
		}
		request := transport.requests[0]
		expectedURL, expectedKey, expectedTimeout := "http://127.0.0.1:18101/v1/models", cfg.CPAAPIKey, 10*time.Second
		if target == "fallback" {
			expectedURL, expectedKey, expectedTimeout = "http://127.0.0.1:18102/v1/models", cfg.FallbackCPAKey, 600*time.Second
		}
		if request.URL != expectedURL || request.Headers.Get("Authorization") != "Bearer "+expectedKey {
			t.Fatal("model list used another reviewer's connection")
		}
		if remaining := transport.deadlines[0]; remaining > expectedTimeout || remaining < expectedTimeout-time.Second {
			t.Fatal("model list used the wrong timeout")
		}
		app.Close()
	}
}

func TestFallbackCPAProbeAndSecretMasking(t *testing.T) {
	verdict := `{"is_violation":false,"confidence":99,"categories":[],"reason":"Safe test input."}`
	completion, _ := json.Marshal(map[string]any{"choices": []any{map[string]any{"message": map[string]string{"content": verdict}, "finish_reason": "stop"}}})
	transport := &captureTransport{response: completion}
	app := New(transport, nil)
	defer app.Close()
	cfg := reviewerConfig()
	raw, _ := json.Marshal(cfg)
	registration, _ := json.Marshal(map[string]any{"config_yaml": raw})
	if _, err := app.Handle("plugin.register", registration); err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]any{"target": "fallback", "config": cfg})
	response := app.management(pluginapi.ManagementRequest{Method: "POST", Path: managementBase + "/test", Body: body}, "scope")
	if response.StatusCode != 200 || !strings.Contains(string(response.Body), `"success":true`) {
		t.Fatalf("probe failed: %s", response.Body)
	}
	request := transport.requests[0]
	if request.URL != "http://127.0.0.1:18102/v1/chat/completions" || request.Headers.Get("Authorization") != "Bearer "+cfg.FallbackCPAKey {
		t.Fatal("probe did not use fallback CPA")
	}
	var payload map[string]any
	_ = json.Unmarshal(request.Body, &payload)
	if payload["model"] != cfg.FallbackModel {
		t.Fatal("probe used the wrong model")
	}
	health := app.management(pluginapi.ManagementRequest{Method: "GET", Path: managementBase + "/health"}, "scope")
	if strings.Contains(string(health.Body), cfg.FallbackCPAKey) {
		t.Fatal("health exposed fallback CPA key")
	}
}

func TestValidationRejectsTimeoutsBeforeSave(t *testing.T) {
	app := New(unusedTransport{}, nil)
	defer app.Close()
	for _, field := range []string{"primary_timeout", "fallback_timeout"} {
		for _, value := range []string{"1", "601", "null", `"10s"`, `"10"`} {
			response := app.management(pluginapi.ManagementRequest{Method: "POST", Path: managementBase + "/validate", Body: []byte(fmt.Sprintf(`{"threshold":0,%q:%s}`, field, value))}, "scope")
			if response.StatusCode != 400 {
				t.Fatalf("invalid %s=%s accepted", field, value)
			}
		}
		for _, value := range []string{"2", "600"} {
			response := app.management(pluginapi.ManagementRequest{Method: "POST", Path: managementBase + "/validate", Body: []byte(fmt.Sprintf(`{"threshold":0,%q:%s}`, field, value))}, "scope")
			if response.StatusCode != 200 {
				t.Fatalf("boundary rejected: %s", response.Body)
			}
		}
	}
}

func TestInvalidInitialTimeoutKeepsHealthReadable(t *testing.T) {
	app := New(unusedTransport{}, nil)
	defer app.Close()
	body, _ := json.Marshal(map[string]any{"config_yaml": []byte("primary_timeout: .nan")})
	if _, err := app.Handle("plugin.register", body); err != nil {
		t.Fatal(err)
	}
	response := app.management(pluginapi.ManagementRequest{Method: "GET", Path: managementBase + "/health"}, "scope")
	var health struct {
		Ready bool   `json:"ready"`
		Error string `json:"config_error"`
	}
	if json.Unmarshal(response.Body, &health) != nil || health.Ready || health.Error == "" {
		t.Fatal("invalid timeout broke diagnostics")
	}
}
