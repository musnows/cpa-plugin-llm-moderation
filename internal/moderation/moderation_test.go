package moderation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

func TestExtractUserTexts(t *testing.T) {
	cases := []struct {
		name, format, body string
		want               []string
		failure            bool
	}{
		{"chat_roles", "openai", `{"messages":[{"role":"system","content":"secret system"},{"role":"user","content":"one"},{"role":"assistant","content":"not user"},{"role":"tool","content":"not user"},{"role":"user","content":[{"type":"text","text":"two"},{"type":"image_url","image_url":{"url":"x"}}]}]}`, []string{"one", "two"}, false},
		{"claude_tool_result", "claude", `{"messages":[{"role":"user","content":[{"type":"tool_result","content":"ignore this"},{"type":"text","text":"visible"},{"type":"document","source":{}}]}]}`, []string{"visible"}, false},
		{"responses_string", "openai-response", `{"input":"hello","instructions":"ignore this"}`, []string{"hello"}, false},
		{"responses_items", "openai-response", `{"previous_response_id":"old","input":[{"type":"function_call_output","output":"ignore this"},{"role":"user","content":[{"type":"input_text","text":"visible"},{"type":"input_image","image_url":"x"}]},{"role":"developer","content":"ignore this"}]}`, []string{"visible"}, false},
		{"gemini", "gemini", `{"systemInstruction":{"parts":[{"text":"ignore"}]},"contents":[{"role":"model","parts":[{"text":"ignore"}]},{"parts":[{"text":"one"},{"functionResponse":{"response":{"text":"ignore"}}},{"inlineData":{}}]},{"role":"user","parts":[{"text":"two"}]}]}`, []string{"one", "two"}, false},
		{"gemini_cli", "gemini-cli", `{"request":{"contents":[{"parts":[{"text":"nested"}]}]}}`, []string{"nested"}, false},
		{"media_only", "openai", `{"messages":[{"role":"user","content":[{"type":"input_audio","input_audio":{}}]}]}`, []string{}, false},
		{"empty", "openai", `{"messages":[{"role":"user","content":"  "}]}`, []string{}, false},
		{"tool_only", "openai-response", `{"input":[{"type":"function_call_output","output":"not user"}]}`, []string{}, false},
		{"bad_json", "openai", `{`, nil, true},
		{"duplicate_role", "openai", `{"messages":[{"role":"assistant","role":"user","content":"x"}]}`, nil, true},
		{"unknown_user_block", "claude", `{"messages":[{"role":"user","content":[{"type":"mystery","text":"hidden"}]}]}`, nil, true},
		{"missing_messages", "openai", `{}`, nil, true},
		{"null_content", "openai", `{"messages":[{"role":"user","content":null}]}`, nil, true},
		{"bad_text_type", "gemini", `{"contents":[{"parts":[{"text":8}]}]}`, nil, true},
		{"unknown_protocol", "audio", `{}`, nil, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := ExtractUserTexts(c.format, []byte(c.body))
			if (err != nil) != c.failure {
				t.Fatalf("error=%v", err)
			}
			if !c.failure && !reflect.DeepEqual(got, c.want) {
				t.Fatalf("got %#v want %#v", got, c.want)
			}
		})
	}
	if _, err := ExtractUserTexts("openai", []byte(strings.Repeat(" ", MaxInputBytes+1))); err == nil {
		t.Fatal("oversized input accepted")
	}
	largeHistory, _ := json.Marshal(map[string]any{"messages": []map[string]string{{"role": "assistant", "content": strings.Repeat("x", MaxInputBytes+1)}, {"role": "user", "content": "visible"}}})
	if texts, err := ExtractUserTexts("openai", largeHistory); err != nil || !reflect.DeepEqual(texts, []string{"visible"}) {
		t.Fatal("excluded history consumed the review text limit")
	}
}

func verdictJSON(violation bool, confidence float64) string {
	categories := []string{}
	if violation {
		categories = []string{"cybersecurity"}
	}
	raw, _ := json.Marshal(Verdict{IsViolation: violation, Confidence: confidence, Categories: categories, Reason: "A short classification reason."})
	return string(raw)
}
func completion(content string) []byte {
	raw, _ := json.Marshal(map[string]any{"choices": []any{map[string]any{"message": map[string]any{"role": "assistant", "content": content}, "finish_reason": "stop"}}})
	return raw
}

func TestVerdictValidation(t *testing.T) {
	good := verdictJSON(true, 80)
	for _, raw := range []string{good, "```json\n" + good + "\n```", "```\n" + good + "\n```", verdictJSON(false, 100)} {
		if _, err := ParseVerdict([]byte(raw)); err != nil {
			t.Fatal(err)
		}
	}
	bad := []string{
		`{"is_violation":true,"confidence":80,"categories":["cybersecurity"]}`,
		`{"is_violation":"true","confidence":80,"categories":["cybersecurity"],"reason":"x"}`,
		`{"is_violation":true,"confidence":101,"categories":["cybersecurity"],"reason":"x"}`,
		`{"is_violation":true,"confidence":-1,"categories":["cybersecurity"],"reason":"x"}`,
		`{"is_violation":false,"confidence":99,"categories":["cybersecurity"],"reason":"x"}`,
		`{"is_violation":true,"confidence":99,"categories":[],"reason":"x"}`,
		`{"is_violation":true,"confidence":99,"categories":["other"],"reason":"x"}`,
		`{"is_violation":true,"confidence":99,"categories":["cybersecurity","cybersecurity"],"reason":"x"}`,
		`{"is_violation":true,"confidence":null,"categories":["cybersecurity"],"reason":"x"}`,
		`{"is_violation":true,"confidence":99,"confidence":0,"categories":["cybersecurity"],"reason":"x"}`,
		`{"is_violation":true,"confidence":99,"categories":["cybersecurity"],"reason":"x","extra":1}`,
		"Here is the JSON: " + good, good + "{}", "```text\n" + good + "\n```", good[:len(good)-1],
	}
	for i, raw := range bad {
		if _, err := ParseVerdict([]byte(raw)); err == nil {
			t.Errorf("case %d accepted invalid verdict", i)
		}
	}
	if _, err := ParseCompletion(completion(good)); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{`{"choices":[]}`, `{"choices":[{"finish_reason":"length","message":{"content":"{}"}}]}`, `{"choices":[{"finish_reason":"stop","message":{"content":"{}","refusal":"refused"}}]}`} {
		if _, err := ParseCompletion([]byte(raw)); err == nil {
			t.Fatal("bad completion accepted")
		}
	}
}

type transportFunc func(context.Context, string, HTTPRequest) (HTTPResponse, error)

func (f transportFunc) Do(ctx context.Context, id string, r HTTPRequest) (HTTPResponse, error) {
	return f(ctx, id, r)
}

type memorySink struct {
	records []Record
	fail    bool
}

func (s *memorySink) Append(r Record) error {
	s.records = append(s.records, r)
	if s.fail {
		return errors.New("disk_failed")
	}
	return nil
}

type memoryLogger struct {
	calls  int
	fields map[string]any
}

func (l *memoryLogger) Log(_, _, _ string, fields map[string]any) { l.calls++; l.fields = fields }
func testConfig() Config {
	c := DefaultConfig()
	c.PrimaryMode = "external"
	c.PrimaryEndpoint = "http://127.0.0.1:18001/v1/chat/completions"
	c.PrimaryModel = "primary"
	c.PrimaryAPIKey = "primary-secret-token"
	c.FallbackEndpoint = "http://127.0.0.1:18002/v1/chat/completions"
	c.FallbackModel = "fallback"
	c.FallbackAPIKey = "fallback-secret-token"
	return c
}
func testRequest() pluginapi.RequestInterceptRequest {
	return pluginapi.RequestInterceptRequest{RequestID: "test-request", TraceID: "test-trace", Model: "target", RequestedModel: "target-alias", SourceFormat: "openai", Body: []byte(`{"messages":[{"role":"user","content":"hello"}]}`), Headers: http.Header{"Authorization": {"Bearer caller-secret-token"}}, Metadata: map[string]any{"caller_scope": CallerFingerprint("caller-secret-token")}}
}

func TestEngineThresholds(t *testing.T) {
	for _, c := range []struct {
		name               string
		threshold, score   float64
		violation, blocked bool
		calls              int
	}{{"zero", 0, 0, false, true, 0}, {"equal", 80, 80, true, false, 1}, {"above", 80, 80.1, true, true, 1}, {"safe_high_confidence", 80, 99, false, false, 1}, {"hundred", 100, 100, true, false, 1}} {
		t.Run(c.name, func(t *testing.T) {
			calls := 0
			engine := NewEngine(transportFunc(func(ctx context.Context, id string, req HTTPRequest) (HTTPResponse, error) {
				calls++
				if req.Headers.Get("Authorization") != "Bearer primary-secret-token" {
					t.Fatal("wrong reviewer credentials")
				}
				if strings.Contains(string(req.Body), "caller-secret-token") {
					t.Fatal("caller key leaked")
				}
				return HTTPResponse{StatusCode: 200, Body: completion(verdictJSON(c.violation, c.score))}, nil
			}), nil)
			cfg := testConfig()
			cfg.Threshold = c.threshold
			sink := &memorySink{}
			out := engine.Intercept(context.Background(), "callback", testRequest(), cfg, nil, sink)
			if out.Terminate != c.blocked || calls != c.calls || len(sink.records) != 1 {
				t.Fatalf("blocked=%v calls=%d records=%d", out.Terminate, calls, len(sink.records))
			}
			if c.blocked && out.StatusCode != 403 {
				t.Fatal("incorrect status")
			}
			if c.threshold == 0 && (sink.records[0].Confidence != nil || sink.records[0].ReviewTotalMS != 0) {
				t.Fatal("zero threshold should not review")
			}
			if sink.records[0].MaskedKey != "call...oken" {
				t.Fatal("incorrect key mask")
			}
		})
	}
}

func TestFallbackAndFailures(t *testing.T) {
	for _, mode := range []string{"http", "invalid_json", "timeout", "canceled", "both_fail_allow", "both_fail_deny"} {
		t.Run(mode, func(t *testing.T) {
			calls := 0
			primaryStopped := false
			cfg := testConfig()
			cfg.FallbackEnabled = true
			cfg.PrimaryTimeout = "5ms"
			if mode == "both_fail_allow" {
				cfg.FailurePolicy = "allow"
			}
			engine := NewEngine(transportFunc(func(ctx context.Context, id string, req HTTPRequest) (HTTPResponse, error) {
				calls++
				if calls == 1 {
					switch mode {
					case "timeout":
						<-ctx.Done()
						primaryStopped = true
						return HTTPResponse{}, ctx.Err()
					case "canceled":
						return HTTPResponse{}, context.Canceled
					case "invalid_json":
						return HTTPResponse{StatusCode: 200, Body: completion("not json")}, nil
					default:
						return HTTPResponse{StatusCode: 502}, nil
					}
				}
				if mode == "timeout" && !primaryStopped {
					t.Fatal("fallback started before cancellation")
				}
				if strings.HasPrefix(mode, "both_fail") {
					return HTTPResponse{StatusCode: 503}, nil
				}
				if req.Headers.Get("Authorization") != "Bearer fallback-secret-token" {
					t.Fatal("wrong fallback credentials")
				}
				return HTTPResponse{StatusCode: 200, Body: completion(verdictJSON(false, 98))}, nil
			}), nil)
			sink := &memorySink{}
			out := engine.Intercept(context.Background(), "callback", testRequest(), cfg, nil, sink)
			r := sink.records[0]
			if mode == "canceled" {
				if calls != 1 || r.Decision != "canceled" {
					t.Fatal("cancellation triggered fallback")
				}
				return
			}
			if calls != 2 || !r.FallbackUsed || len(r.Attempts) != 2 {
				t.Fatalf("missing fallback: %+v", r)
			}
			if mode == "both_fail_deny" && (!out.Terminate || out.StatusCode != 503) {
				t.Fatal("failed open")
			}
			if mode == "both_fail_allow" && (out.Terminate || r.Decision != "error_allowed") {
				t.Fatal("did not fail open")
			}
			if mode == "timeout" && r.PrimaryDurationMS < 4 {
				t.Fatal("timeout duration missing")
			}
		})
	}
}

func TestNonceBindingAndReplay(t *testing.T) {
	n := NewNonces()
	body := []byte(`{"model":"review","messages":[]}`)
	token, err := n.Issue(body, "review-key", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	meta := map[string]any{"caller_scope": CallerFingerprint("review-key")}
	if n.Consume(token, []byte(`{"model":"other"}`), meta) {
		t.Fatal("modified request bypassed")
	}
	if n.Consume(token, body, map[string]any{"caller_scope": CallerFingerprint("other")}) {
		t.Fatal("wrong caller bypassed")
	}
	if !n.Consume(token, body, meta) {
		t.Fatal("valid nonce rejected")
	}
	if n.Consume(token, body, meta) {
		t.Fatal("nonce replay accepted")
	}
	if n.Consume("forged", body, meta) {
		t.Fatal("forgery accepted")
	}
}

func TestInternalBypassAndLogRedaction(t *testing.T) {
	logger := &memoryLogger{}
	engine := NewEngine(transportFunc(func(context.Context, string, HTTPRequest) (HTTPResponse, error) {
		return HTTPResponse{StatusCode: 200, Body: completion(`{"is_violation":false,"confidence":99,"categories":[],"reason":"caller-secret-token primary-secret-token hello"}`)}, nil
	}), logger)
	req := testRequest()
	token, _ := engine.Nonces.Issue(req.Body, "caller-secret-token", time.Minute)
	req.Headers.Set(InternalHeader, token)
	sink := &memorySink{}
	cfg := testConfig()
	out := engine.Intercept(context.Background(), "callback", req, cfg, nil, sink)
	if out.Terminate || len(sink.records) != 0 || len(out.ClearHeaders) != 1 {
		t.Fatal("internal request was audited")
	}
	sink.fail = true
	engine.Intercept(context.Background(), "callback", req, cfg, nil, sink)
	raw, _ := json.Marshal(sink.records[0])
	for _, s := range []string{"caller-secret-token", "primary-secret-token", "hello"} {
		if strings.Contains(string(raw), s) {
			t.Fatalf("secret or prompt leaked: %s", s)
		}
	}
	if logger.calls != 1 {
		t.Fatal("disk failure not reported")
	}
}

func TestConfigAndIdentity(t *testing.T) {
	cfg := testConfig()
	raw, _ := json.Marshal(cfg)
	if _, err := ParseConfig(raw); err != nil {
		t.Fatal(err)
	}
	for _, change := range []string{`{"threshold":101}`, `{"primary_mode":"bad"}`, `{"primary_timeout":"0s"}`, `{"failure_policy":"guess"}`, `{"log_dir":""}`} {
		if _, err := ParseConfig([]byte(change)); err == nil {
			t.Fatal("invalid config accepted")
		}
	}
	if _, err := ParseConfig([]byte(`{"threshold":0}`)); err != nil {
		t.Fatal("block-all configuration requires a reviewer")
	}
	if _, err := ParseConfig([]byte(`{"enabled":false}`)); err != nil {
		t.Fatal(err)
	}
	h := http.Header{"Authorization": {"Bearer forged-client-key"}, "X-Api-Key": {"actual-client-key"}}
	fp, mask := Identify(h, map[string]any{"caller_scope": CallerFingerprint("actual-client-key")})
	if fp != CallerFingerprint("actual-client-key") || mask != "actu...-key" {
		t.Fatal("logged an unauthenticated key")
	}
}

func TestInternalFailureIsAuditedAndClosed(t *testing.T) {
	engine := NewEngine(transportFunc(func(context.Context, string, HTTPRequest) (HTTPResponse, error) { panic("synthetic internal failure") }), nil)
	sink := &memorySink{}
	response := engine.Intercept(context.Background(), "scope", testRequest(), testConfig(), nil, sink)
	if !response.Terminate || response.StatusCode != 503 || len(sink.records) != 1 || sink.records[0].Decision != "error_denied" {
		t.Fatal("internal failure was not safely recorded")
	}
}

func TestFileStorePersistencePaginationAndStatistics(t *testing.T) {
	dir := t.TempDir()
	s := NewFileStore(dir)
	now := time.Now().UTC().Truncate(time.Second)
	var wg sync.WaitGroup
	for i := 0; i < 80; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			r := Record{Time: now.Add(time.Duration(i) * time.Millisecond), RequestID: fmt.Sprintf("request-%03d", i), Decision: "allow", TargetModel: "target", KeyFingerprint: "key", PrecheckDurationMS: float64(i + 1), Attempts: []Attempt{{Reviewer: "primary", DurationMS: float64(i + 1)}}}
			if i%2 == 0 {
				r.Decision = "block"
			}
			if err := s.Append(r); err != nil {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
	reopened := NewFileStore(dir)
	filter := Filter{From: now.Add(-time.Hour), To: now.Add(time.Hour), Limit: 25}
	seen := map[string]bool{}
	for {
		page, err := reopened.Records(filter)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range page.Records {
			if seen[r.RequestID] {
				t.Fatal("duplicate pagination record")
			}
			seen[r.RequestID] = true
		}
		if page.NextCursor == "" {
			break
		}
		filter.Cursor = page.NextCursor
	}
	if len(seen) != 80 {
		t.Fatalf("got %d records", len(seen))
	}
	summary, err := reopened.Summary(filter)
	if err != nil {
		t.Fatal(err)
	}
	if summary.Requests != 80 || summary.Blocked != 40 || summary.Primary.P50MS != 40 || summary.Primary.P95MS != 76 {
		t.Fatalf("wrong summary: %+v", summary)
	}
	f, err := os.OpenFile(filepath.Join(dir, now.Format("2006-01-02")+".jsonl"), os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString("corrupt line\n{\"partial\":")
	_ = f.Close()
	page, err := reopened.Records(filter)
	if err != nil || page.CorruptLines != 2 {
		t.Fatalf("corrupt lines: %+v %v", page, err)
	}
	if err := reopened.Append(Record{Time: now, RequestID: "after-restart", Decision: "allow"}); err != nil {
		t.Fatal(err)
	}
	summary, err = reopened.Summary(filter)
	if err != nil || summary.Requests != 81 {
		t.Fatal("restart did not recover after partial tail")
	}
}
