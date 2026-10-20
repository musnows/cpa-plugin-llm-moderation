package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/musnows/cpa-plugin-llm-moderation/internal/moderation"
	"gopkg.in/yaml.v3"
)

type policyCase struct {
	ID           string   `json:"id"`
	UserMessages []string `json:"user_messages"`
	IsViolation  bool     `json:"is_violation"`
}

type result struct {
	CaseID           string              `json:"case_id"`
	Reviewer         string              `json:"reviewer"`
	Model            string              `json:"model"`
	Expected         bool                `json:"expected_violation"`
	Passed           bool                `json:"passed"`
	Blocked          bool                `json:"blocked_at_threshold"`
	Verdict          *moderation.Verdict `json:"verdict,omitempty"`
	Attempt          moderation.Attempt  `json:"attempt"`
	GatewayDenied    bool                `json:"gateway_denied,omitempty"`
	GatewayRequestID string              `json:"gateway_request_id,omitempty"`
}

type transport struct {
	client       *http.Client
	policyDenial bool
	requestID    string
}

func (t *transport) Do(ctx context.Context, _ string, input moderation.HTTPRequest) (moderation.HTTPResponse, error) {
	t.policyDenial, t.requestID = false, ""
	req, err := http.NewRequestWithContext(ctx, input.Method, input.URL, bytes.NewReader(input.Body))
	if err != nil {
		return moderation.HTTPResponse{}, errors.New("invalid_review_request")
	}
	req.Header = input.Headers.Clone()
	response, err := t.client.Do(req)
	if err != nil {
		return moderation.HTTPResponse{}, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, moderation.MaxResponseBytes+1))
	var denial struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
		RequestID string `json:"request_id"`
	}
	if response.StatusCode == http.StatusForbidden && json.Unmarshal(body, &denial) == nil && denial.Error.Code == "content_policy_violation" {
		t.policyDenial, t.requestID = true, denial.RequestID
	}
	return moderation.HTTPResponse{StatusCode: response.StatusCode, Headers: response.Header, Body: body}, err
}

func loadConfig(path string) (moderation.Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return moderation.Config{}, errors.New("cannot_read_config")
	}
	var root struct {
		Plugins struct {
			Configs map[string]yaml.Node `yaml:"configs"`
		} `yaml:"plugins"`
	}
	if yaml.Unmarshal(raw, &root) != nil {
		return moderation.Config{}, errors.New("invalid_host_config")
	}
	node, ok := root.Plugins.Configs[moderation.ID]
	if !ok {
		return moderation.Config{}, errors.New("moderation_config_missing")
	}
	encoded, err := yaml.Marshal(&node)
	if err != nil {
		return moderation.Config{}, errors.New("invalid_moderation_config")
	}
	return moderation.ParseConfig(encoded)
}

func main() {
	configPath := flag.String("config", "", "CPA config path; keys are read locally and never printed")
	casesPath := flag.String("cases", "testsupport/policy-cases.json", "Synthetic policy cases")
	outputPath := flag.String("output", "", "Evaluation result JSON path")
	reviewers := flag.String("reviewers", "primary", "primary, fallback, or both")
	limit := flag.Int("limit", 0, "Maximum cases; zero runs all cases")
	promptPath := flag.String("prompt-file", "", "Optional system prompt file for baseline comparison")
	endToEnd := flag.Bool("end-to-end", false, "Accept an explicit gateway content-policy denial as an expected block; do not treat it as a model verdict")
	timeout := flag.Duration("timeout", 0, "Optional evaluation HTTP deadline; production reviewer timeouts are unchanged")
	flag.Parse()
	if err := run(*configPath, *casesPath, *outputPath, *reviewers, *limit, *promptPath, *endToEnd, *timeout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(configPath, casesPath, outputPath, reviewers string, limit int, promptPath string, endToEnd bool, timeout time.Duration) error {
	if configPath == "" || outputPath == "" || limit < 0 || timeout < 0 || (reviewers != "primary" && reviewers != "fallback" && reviewers != "both") {
		return errors.New("invalid_evaluation_arguments")
	}
	cfg, err := loadConfig(configPath)
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(casesPath)
	var cases []policyCase
	if err != nil || json.Unmarshal(raw, &cases) != nil || len(cases) == 0 {
		return errors.New("invalid_policy_cases")
	}
	if limit > 0 && len(cases) > limit {
		cases = cases[:limit]
	}
	cfg.PromptMode, cfg.AppendPrompt, cfg.OverridePrompt = "append", "", ""
	if promptPath != "" {
		prompt, err := os.ReadFile(promptPath)
		if err != nil || len(prompt) == 0 {
			return errors.New("invalid_prompt_file")
		}
		cfg.PromptMode, cfg.OverridePrompt = "override", string(prompt)
	}
	selected := []moderation.Reviewer{}
	if reviewers == "primary" || reviewers == "both" {
		selected = append(selected, cfg.Primary())
	}
	if reviewers == "fallback" || reviewers == "both" {
		if !cfg.FallbackEnabled {
			return errors.New("fallback_not_enabled")
		}
		selected = append(selected, cfg.Fallback())
	}
	client := &transport{client: &http.Client{CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}}
	engine := moderation.NewEngine(client, nil)
	results := []result{}
	passed := true
	for _, reviewer := range selected {
		if timeout > 0 {
			reviewer.Timeout = timeout
		}
		for _, sample := range cases {
			if sample.ID == "" || len(sample.UserMessages) == 0 {
				return errors.New("invalid_policy_case")
			}
			verdict, attempt, err := engine.Review(context.Background(), "policy-eval", reviewer, sample.UserMessages)
			item := result{CaseID: sample.ID, Reviewer: reviewer.Name, Model: reviewer.Model, Expected: sample.IsViolation, Attempt: attempt}
			item.GatewayDenied, item.GatewayRequestID = client.policyDenial, client.requestID
			if err == nil {
				item.Verdict = &verdict
				item.Blocked = verdict.IsViolation && verdict.Confidence > cfg.Threshold
				item.Passed = verdict.IsViolation == sample.IsViolation && (!sample.IsViolation || len(verdict.Categories) == 1 && verdict.Categories[0] == "cybersecurity")
			} else if endToEnd && item.GatewayDenied && item.GatewayRequestID != "" {
				item.Blocked = true
				item.Passed = sample.IsViolation
			}
			passed = passed && item.Passed
			results = append(results, item)
			fmt.Printf("case=%s reviewer=%s passed=%t outcome=%s\n", sample.ID, reviewer.Name, item.Passed, attempt.Outcome)
		}
	}
	report := map[string]any{"passed": passed, "count": len(results), "end_to_end": endToEnd, "prompt_sha256": cfg.PromptHash(), "threshold": cfg.Threshold, "completed_at": time.Now().UTC(), "results": results}
	encoded, _ := json.MarshalIndent(report, "", "  ")
	if os.WriteFile(outputPath, encoded, 0600) != nil {
		return errors.New("cannot_write_evaluation_result")
	}
	if !passed {
		return errors.New("policy_evaluation_failed")
	}
	return nil
}
