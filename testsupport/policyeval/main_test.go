package main

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/musnows/cpa-plugin-llm-moderation/internal/moderation"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func TestGatewayDenialIsNotAnAuthenticationOrAvailabilityFailure(t *testing.T) {
	for _, item := range []struct {
		status int
		body   string
		policy bool
	}{
		{403, `{"error":{"code":"content_policy_violation"},"request_id":"test-id"}`, true},
		{403, `{"error":{"code":"invalid_api_key"}}`, false},
		{503, `{"error":{"code":"moderation_unavailable"}}`, false},
		{429, `{"error":{"code":"rate_limit_exceeded"}}`, false},
		{200, `{"error":{"code":"content_policy_violation"},"request_id":"test-id"}`, false},
		{403, `<html>Access denied</html>`, false},
	} {
		client := &transport{client: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			if req.Header.Get("Authorization") != "Bearer test-key" {
				t.Fatal("review authentication was not forwarded to the configured endpoint")
			}
			return &http.Response{StatusCode: item.status, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(item.body))}, nil
		})}}
		_, err := client.Do(context.Background(), "test", moderation.HTTPRequest{Method: "POST", URL: "https://review.example.test/v1/chat/completions", Headers: http.Header{"Authorization": {"Bearer test-key"}}, Body: []byte(`{}`)})
		if err != nil || client.policyDenial != item.policy {
			t.Fatalf("incorrect gateway denial classification for status %d", item.status)
		}
		if item.policy && client.requestID != "test-id" {
			t.Fatal("gateway request ID was not retained for audit correlation")
		}
	}
}
