package moderation

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestPromptConfigurationDefaultsAndValidation(t *testing.T) {
	cfg, err := ParseConfig([]byte(`{"threshold":0}`))
	if err != nil || cfg.PromptMode != "append" || cfg.EffectivePrompt() != SystemPrompt {
		t.Fatal("existing configurations must keep the built-in prompt")
	}
	for _, raw := range []string{
		`{"threshold":0,"prompt_mode":"invalid"}`,
		`{"threshold":0,"prompt_mode":"override"}`,
		`{"threshold":0,"prompt_mode":"override","override_prompt":" \n\t"}`,
	} {
		if _, err := ParseConfigWrite([]byte(raw)); err == nil {
			t.Fatalf("accepted invalid prompt settings: %s", raw)
		}
	}
	for _, field := range []string{"prompt_mode", "append_prompt", "override_prompt"} {
		for _, value := range []string{"null", "42", "true", "[]", "{}"} {
			raw := fmt.Sprintf(`{"threshold":0,%q:%s}`, field, value)
			if _, err := ParseConfigWrite([]byte(raw)); err == nil {
				t.Fatalf("accepted invalid prompt type: %s", raw)
			}
		}
	}
	cfg.AppendPrompt, cfg.OverridePrompt = "  Additional rule.\n", "  Complete replacement.\n"
	if got := cfg.EffectivePrompt(); got != SystemPrompt+"\n\nAdditional review instructions:\n"+cfg.AppendPrompt {
		t.Fatal("append mode changed or replaced the built-in prompt")
	}
	cfg.PromptMode = "override"
	if err := cfg.Validate(); err != nil || cfg.EffectivePrompt() != cfg.OverridePrompt {
		t.Fatal("override mode must replace the entire system prompt verbatim")
	}
	cfg.PromptMode = "append"
	cfg.AppendPrompt = " \n"
	if cfg.EffectivePrompt() != SystemPrompt {
		t.Fatal("blank append must preserve the original prompt")
	}
}

func TestPrimaryAndFallbackUsePromptSnapshot(t *testing.T) {
	for _, mode := range []string{"append", "override"} {
		t.Run(mode, func(t *testing.T) {
			cfg := testConfig()
			cfg.PromptMode, cfg.AppendPrompt, cfg.OverridePrompt = mode, "Additional review rule.", "Replacement review policy."
			cfg.FallbackEnabled = true
			expectedPrompt, expectedHash := cfg.EffectivePrompt(), cfg.PromptHash()
			calls := 0
			engine := NewEngine(transportFunc(func(_ context.Context, _ string, req HTTPRequest) (HTTPResponse, error) {
				calls++
				var payload struct {
					Messages []struct{ Role, Content string } `json:"messages"`
				}
				if json.Unmarshal(req.Body, &payload) != nil || len(payload.Messages) != 2 {
					t.Fatal("invalid review messages")
				}
				if payload.Messages[0].Role != "system" || payload.Messages[0].Content != expectedPrompt {
					t.Fatal("reviewer did not receive the configuration snapshot")
				}
				var evidence struct {
					UserMessages []string `json:"user_messages"`
				}
				if payload.Messages[1].Role != "user" || json.Unmarshal([]byte(payload.Messages[1].Content), &evidence) != nil || len(evidence.UserMessages) != 1 || evidence.UserMessages[0] != "hello" {
					t.Fatal("user input was merged with system instructions")
				}
				cfg.AppendPrompt, cfg.OverridePrompt = "Changed after request start.", "Changed after request start."
				if calls == 1 {
					return HTTPResponse{StatusCode: 503}, nil
				}
				return HTTPResponse{StatusCode: 200, Body: completion(verdictJSON(false, 99))}, nil
			}), nil)
			sink := &memorySink{}
			response := engine.Intercept(context.Background(), "scope", testRequest(), cfg, nil, sink)
			if response.Terminate || calls != 2 || len(sink.records) != 1 {
				t.Fatal("fallback did not complete")
			}
			record := sink.records[0]
			if record.PromptMode != mode || record.PromptSHA256 != expectedHash {
				t.Fatal("audit did not identify the effective prompt")
			}
			raw, _ := json.Marshal(record)
			if strings.Contains(string(raw), "Additional review rule") || strings.Contains(string(raw), "Replacement review policy") {
				t.Fatal("audit stored custom prompt text")
			}
		})
	}
}
