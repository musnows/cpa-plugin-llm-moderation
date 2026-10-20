package plugin

import (
	"encoding/json"
	"testing"

	"github.com/musnows/cpa-plugin-llm-moderation/internal/moderation"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

func TestPromptTemplateAndDraftReviewerSettings(t *testing.T) {
	completion, _ := json.Marshal(map[string]any{"choices": []any{map[string]any{"message": map[string]string{"content": `{"is_violation":false,"confidence":99,"categories":[],"reason":"Safe input."}`}, "finish_reason": "stop"}}})
	transport := &captureTransport{response: completion}
	app := New(transport, nil)
	defer app.Close()
	template := app.management(pluginapi.ManagementRequest{Method: "GET", Path: managementBase + "/prompt"}, "scope")
	var result map[string]string
	if template.StatusCode != 200 || json.Unmarshal(template.Body, &result) != nil || result["system_prompt"] != moderation.SystemPrompt {
		t.Fatal("template differs from the built-in prompt")
	}
	for _, mode := range []string{"append", "override"} {
		for _, target := range []string{"primary", "fallback"} {
			cfg := reviewerConfig()
			cfg.PromptMode, cfg.AppendPrompt, cfg.OverridePrompt = mode, "Extra rule.", "Complete replacement."
			body, _ := json.Marshal(map[string]any{"target": target, "config": cfg})
			response := app.management(pluginapi.ManagementRequest{Method: "POST", Path: managementBase + "/test", Body: body}, "scope")
			if response.StatusCode != 200 {
				t.Fatalf("draft probe failed: %s", response.Body)
			}
			var payload struct {
				Messages []struct{ Role, Content string } `json:"messages"`
			}
			_ = json.Unmarshal(transport.requests[len(transport.requests)-1].Body, &payload)
			if len(payload.Messages) != 2 || payload.Messages[0].Content != cfg.EffectivePrompt() {
				t.Fatal("draft probe ignored custom prompt")
			}
		}
	}
}
