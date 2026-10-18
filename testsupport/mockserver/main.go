package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

type event struct {
	Time  time.Time `json:"time"`
	Kind  string    `json:"kind"`
	Model string    `json:"model"`
	Auth  string    `json:"auth"`
	Nonce string    `json:"nonce"`
}

var mu sync.Mutex
var events []event

func record(r *http.Request, kind, model string) {
	mu.Lock()
	defer mu.Unlock()
	events = append(events, event{Time: time.Now().UTC(), Kind: kind, Model: model, Auth: r.Header.Get("Authorization"), Nonce: r.Header.Get("X-CPA-Moderation-Nonce")})
}
func write(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func main() {
	port := flag.Int("port", 19080, "Preferred test port, at least 10000")
	state := flag.String("state", "", "Path to write the bound test address")
	flag.Parse()
	if *port < 10000 {
		fmt.Fprintln(os.Stderr, "Port must be at least 10000")
		os.Exit(1)
	}
	var listener net.Listener
	var err error
	for candidate := *port; candidate < *port+100; candidate++ {
		listener, err = net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(candidate))
		if err == nil {
			break
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "No test port available")
		os.Exit(1)
	}
	if *state != "" {
		raw, _ := json.Marshal(map[string]string{"base_url": "http://" + listener.Addr().String()})
		if os.WriteFile(*state, raw, 0600) != nil {
			os.Exit(1)
		}
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) { write(w, 200, map[string]bool{"ok": true}) })
	mux.HandleFunc("/events", func(w http.ResponseWriter, r *http.Request) { mu.Lock(); defer mu.Unlock(); write(w, 200, events) })
	mux.HandleFunc("/v1/models", func(w http.ResponseWriter, r *http.Request) {
		var data []map[string]string
		for _, id := range []string{"target-model", "review-via-cpa", "review-block", "review-slow", "review-timeout"} {
			data = append(data, map[string]string{"id": id, "object": "model", "owned_by": "fixture"})
		}
		write(w, 200, map[string]any{"object": "list", "data": data})
	})
	mux.HandleFunc("/", complete)
	fmt.Println("Fixture listening at http://" + listener.Addr().String())
	if err := http.Serve(listener, mux); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func complete(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" || !strings.HasSuffix(r.URL.Path, "/chat/completions") {
		http.NotFound(w, r)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 8<<20))
	if err != nil {
		write(w, 400, map[string]string{"error": "read_failed"})
		return
	}
	var request struct {
		Model    string `json:"model"`
		Stream   bool   `json:"stream"`
		Messages []struct {
			Role    string
			Content json.RawMessage
		} `json:"messages"`
	}
	if json.Unmarshal(body, &request) != nil {
		write(w, 400, map[string]string{"error": "invalid_json"})
		return
	}
	if strings.HasPrefix(request.Model, "review-") {
		record(r, "review", request.Model)
		if request.Model == "review-timeout" {
			select {
			case <-r.Context().Done():
				record(r, "review_canceled", request.Model)
				return
			case <-time.After(45 * time.Second):
				write(w, 504, map[string]string{"error": "timeout"})
				return
			}
		}
		if request.Model == "review-fail" {
			write(w, 503, map[string]string{"error": "synthetic_failure"})
			return
		}
		delay := 25 * time.Millisecond
		if request.Model == "review-slow" {
			delay = 120 * time.Millisecond
		}
		select {
		case <-r.Context().Done():
			record(r, "review_canceled", request.Model)
			return
		case <-time.After(delay):
		}
		content := strings.Join(func() []string {
			var result []string
			for _, m := range request.Messages {
				if m.Role == "user" {
					var text string
					if json.Unmarshal(m.Content, &text) != nil {
						text = string(m.Content)
					}
					result = append(result, text)
				}
			}
			return result
		}(), "\n")
		violation := strings.Contains(content, "TEST_BLOCK") || request.Model == "review-block"
		confidence := 99.0
		if violation {
			confidence = 92
		}
		if strings.Contains(content, "TEST_BOUNDARY") {
			violation = true
			confidence = 80
		}
		if strings.Contains(content, "TEST_LOW") {
			violation = true
			confidence = 50
		}
		categories := []string{}
		if violation {
			categories = []string{"cybersecurity"}
		}
		verdict, _ := json.Marshal(map[string]any{"is_violation": violation, "confidence": confidence, "categories": categories, "reason": "Deterministic fixture classification."})
		text := string(verdict)
		finish := "stop"
		if request.Model == "review-invalid" {
			text = "invalid JSON"
		}
		if request.Model == "review-truncated" {
			finish = "length"
		}
		write(w, 200, map[string]any{"id": "chatcmpl-review", "object": "chat.completion", "created": time.Now().Unix(), "model": request.Model, "choices": []any{map[string]any{"index": 0, "message": map[string]string{"role": "assistant", "content": text}, "finish_reason": finish}}, "usage": map[string]int{"prompt_tokens": 10, "completion_tokens": 20, "total_tokens": 30}})
		return
	}
	record(r, "target", request.Model)
	if !request.Stream {
		write(w, 200, map[string]any{"id": "chatcmpl-target", "object": "chat.completion", "created": time.Now().Unix(), "model": request.Model, "choices": []any{map[string]any{"index": 0, "message": map[string]string{"role": "assistant", "content": "Fixture response."}, "finish_reason": "stop"}}, "usage": map[string]int{"prompt_tokens": 5, "completion_tokens": 3, "total_tokens": 8}})
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(200)
	for i, delta := range []map[string]string{{"role": "assistant", "content": ""}, {"content": "Fixture response."}, {}} {
		var finish any
		if i == 2 {
			finish = "stop"
		}
		payload, _ := json.Marshal(map[string]any{"id": "chatcmpl-target", "object": "chat.completion.chunk", "created": time.Now().Unix(), "model": request.Model, "choices": []any{map[string]any{"index": 0, "delta": delta, "finish_reason": finish}}})
		fmt.Fprintf(w, "data: %s\n\n", payload)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
	}
	fmt.Fprint(w, "data: [DONE]\n\n")
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
}
