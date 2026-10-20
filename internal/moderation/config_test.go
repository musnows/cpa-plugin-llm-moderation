package moderation

import (
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"testing"
	"time"
)

func TestTimeoutSecondsBoundsAndWriteTypes(t *testing.T) {
	for _, field := range []string{"primary_timeout", "fallback_timeout"} {
		for _, seconds := range []float64{2, 2.5, 10, 599.999, 600} {
			t.Run(fmt.Sprintf("%s/%g", field, seconds), func(t *testing.T) {
				raw := []byte(fmt.Sprintf(`{"threshold":0,%q:%g}`, field, seconds))
				cfg, err := ParseConfigWrite(raw)
				if err != nil {
					t.Fatal(err)
				}
				got := cfg.PrimaryTimeout
				if field == "fallback_timeout" {
					got = cfg.FallbackTimeout
				}
				if got != seconds {
					t.Fatalf("got %v seconds", got)
				}
			})
		}
		for _, value := range []string{"-1", "0", "1", "1.999", "600.001", "601", "1e999", "null", "true", `"10s"`, `"10"`, `"5m"`, `""`, `[]`, `{}`} {
			raw := []byte(fmt.Sprintf(`{"threshold":0,%q:%s}`, field, value))
			if _, err := ParseConfigWrite(raw); err == nil {
				t.Errorf("accepted invalid %s=%s", field, value)
			}
		}
	}
	for _, invalid := range []float64{math.NaN(), math.Inf(1), math.Inf(-1)} {
		cfg := DefaultConfig()
		cfg.Threshold, cfg.PrimaryTimeout = 0, invalid
		if cfg.Validate() == nil {
			t.Fatal("accepted non-finite timeout")
		}
	}
}

func TestExistingDurationStringsLoadAsNumericSeconds(t *testing.T) {
	for _, item := range []struct {
		raw     string
		seconds float64
	}{{"2s", 2}, {"10s", 10}, {"2m30s", 150}, {"10m", 600}} {
		raw := []byte(fmt.Sprintf("threshold: 0\nprimary_timeout: %s\nfallback_timeout: %s\n", item.raw, item.raw))
		cfg, err := ParseConfig(raw)
		if err != nil {
			t.Fatal(err)
		}
		if cfg.PrimaryTimeout != item.seconds || cfg.FallbackTimeout != item.seconds || cfg.FallbackMode != "external" {
			t.Fatalf("incorrect legacy migration: %+v", cfg)
		}
		encoded, _ := json.Marshal(cfg)
		var stored map[string]any
		_ = json.Unmarshal(encoded, &stored)
		if _, ok := stored["primary_timeout"].(float64); !ok {
			t.Fatal("timeout was not serialized as a number")
		}
		if cfg.Primary().Timeout != time.Duration(item.seconds*float64(time.Second)) {
			t.Fatal("wrong request deadline")
		}
	}
	for _, raw := range []string{"primary_timeout: 150ms", "fallback_timeout: 601s", "primary_timeout: .nan", "fallback_timeout: .inf"} {
		if _, err := ParseConfig([]byte("threshold: 0\n" + raw)); err == nil {
			t.Fatalf("accepted invalid legacy timeout: %s", raw)
		}
	}
}

func TestIndependentPrimaryAndFallbackModes(t *testing.T) {
	for _, primaryMode := range []string{"cpa", "external"} {
		for _, fallbackMode := range []string{"cpa", "external"} {
			cfg := testConfig()
			cfg.PrimaryMode, cfg.FallbackMode, cfg.FallbackEnabled = primaryMode, fallbackMode, true
			cfg.CPABaseURL, cfg.CPAAPIKey = "http://127.0.0.1:18003/main/v1/", "primary-cpa-secret"
			cfg.FallbackCPAURL, cfg.FallbackCPAKey = "http://127.0.0.1:18004/backup/", "fallback-cpa-secret"
			cfg.PrimaryTimeout, cfg.FallbackTimeout = 2, 600
			if err := cfg.Validate(); err != nil {
				t.Fatal(err)
			}
			primary, fallback := cfg.Primary(), cfg.Fallback()
			if primary.Timeout != 2*time.Second || fallback.Timeout != 600*time.Second {
				t.Fatal("timeouts crossed reviewer boundaries")
			}
			if primaryMode == "cpa" && (primary.Endpoint != "http://127.0.0.1:18003/main/v1/chat/completions" || primary.APIKey != cfg.CPAAPIKey) {
				t.Fatal("incorrect primary CPA route")
			}
			if fallbackMode == "cpa" && (fallback.Endpoint != "http://127.0.0.1:18004/backup/v1/chat/completions" || fallback.APIKey != cfg.FallbackCPAKey) {
				t.Fatal("incorrect fallback CPA route")
			}
			if primaryMode == "external" && (primary.Endpoint != cfg.PrimaryEndpoint || primary.APIKey != cfg.PrimaryAPIKey) {
				t.Fatal("incorrect primary external route")
			}
			if fallbackMode == "external" && (fallback.Endpoint != cfg.FallbackEndpoint || fallback.APIKey != cfg.FallbackAPIKey) {
				t.Fatal("incorrect fallback external route")
			}
			if fallback.Model != cfg.FallbackModel {
				t.Fatal("fallback used the primary model")
			}
			if strings.Contains(redact(cfg.FallbackCPAKey, cfg.Secrets()), cfg.FallbackCPAKey) {
				t.Fatal("fallback CPA secret was not redacted")
			}
		}
	}
	cfg := testConfig()
	cfg.FallbackEnabled, cfg.FallbackMode = true, "cpa"
	if cfg.Validate() == nil {
		t.Fatal("missing fallback CPA connection accepted")
	}
	cfg.FallbackCPAURL = "http://127.0.0.1:18004"
	if cfg.Validate() == nil {
		t.Fatal("missing fallback CPA key accepted")
	}
	cfg.FallbackCPAKey = "fallback-cpa-secret"
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestSummaryAllowsTwoLongReviewAttempts(t *testing.T) {
	var durations histogram
	durations.add(900000)
	durations.add(1200000)
	if result := durations.result(); result.P50MS != 900000 || result.P95MS != 1200000 {
		t.Fatalf("long prechecks were truncated: %+v", result)
	}
}
