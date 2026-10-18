package plugin

import (
	"context"
	"encoding/json"
	"github.com/musnows/cpa-plugin-llm-moderation/internal/moderation"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
	"testing"
)

type unusedTransport struct{}

func (unusedTransport) Do(context.Context, string, moderation.HTTPRequest) (moderation.HTTPResponse, error) {
	panic("unexpected transport call")
}
func TestInvalidReconfigurationKeepsActivePolicy(t *testing.T) {
	a := New(unusedTransport{}, nil)
	defer a.Close()
	cfg := moderation.DefaultConfig()
	cfg.Threshold = 0
	cfg.LogDir = t.TempDir()
	raw, _ := json.Marshal(cfg)
	payload, _ := json.Marshal(map[string]any{"config_yaml": raw})
	if _, err := a.Handle("plugin.register", payload); err != nil {
		t.Fatal(err)
	}
	bad, _ := json.Marshal(map[string]any{"config_yaml": []byte("threshold: 101")})
	if _, err := a.Handle("plugin.reconfigure", bad); err != nil {
		t.Fatal("invalid update must not unregister the interceptor")
	}
	if a.state.Load().lastConfigError == "" {
		t.Fatal("rejected update was not reported")
	}
	request, _ := json.Marshal(pluginapi.RequestInterceptRequest{RequestID: "id", SourceFormat: "openai", Body: []byte(`{"messages":[{"role":"user","content":"hello"}]}`)})
	result, err := a.Handle("request.intercept_before", request)
	if err != nil {
		t.Fatal(err)
	}
	response := result.(pluginapi.RequestInterceptResponse)
	if !response.Terminate || response.StatusCode != 403 {
		t.Fatal("previous policy was lost")
	}
}
func TestMalformedHookFailsClosed(t *testing.T) {
	a := New(unusedTransport{}, nil)
	defer a.Close()
	result, err := a.Handle("request.intercept_before", []byte("{"))
	if err != nil || !result.(pluginapi.RequestInterceptResponse).Terminate {
		t.Fatal("invalid request failed open")
	}
}
func TestStaticShellContainsNoConfiguredSecrets(t *testing.T) {
	a := New(unusedTransport{}, nil)
	defer a.Close()
	for _, path := range []string{"dashboard", "app.js", "style.css"} {
		response := a.management(pluginapi.ManagementRequest{Method: "GET", Path: "/v0/resource/plugins/llm-moderation/" + path}, "")
		if response.StatusCode != 200 || len(response.Body) == 0 {
			t.Fatalf("missing resource: %s", path)
		}
	}
}
