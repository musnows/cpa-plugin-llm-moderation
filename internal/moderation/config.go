package moderation

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"net/url"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const ID = "llm-moderation"
const Version = "0.1.0"
const MaxInputBytes = 4 << 20
const MaxRequestBytes = 32 << 20
const MaxResponseBytes = 1 << 20

type Config struct {
	Enabled          bool    `yaml:"enabled" json:"enabled"`
	PrimaryMode      string  `yaml:"primary_mode" json:"primary_mode"`
	CPABaseURL       string  `yaml:"cpa_base_url" json:"cpa_base_url"`
	CPAAPIKey        string  `yaml:"cpa_api_key" json:"cpa_api_key"`
	PrimaryEndpoint  string  `yaml:"primary_endpoint" json:"primary_endpoint"`
	PrimaryAPIKey    string  `yaml:"primary_api_key" json:"primary_api_key"`
	PrimaryModel     string  `yaml:"primary_model" json:"primary_model"`
	PrimaryTimeout   string  `yaml:"primary_timeout" json:"primary_timeout"`
	FallbackEnabled  bool    `yaml:"fallback_enabled" json:"fallback_enabled"`
	FallbackEndpoint string  `yaml:"fallback_endpoint" json:"fallback_endpoint"`
	FallbackAPIKey   string  `yaml:"fallback_api_key" json:"fallback_api_key"`
	FallbackModel    string  `yaml:"fallback_model" json:"fallback_model"`
	FallbackTimeout  string  `yaml:"fallback_timeout" json:"fallback_timeout"`
	Threshold        float64 `yaml:"threshold" json:"threshold"`
	FailurePolicy    string  `yaml:"failure_policy" json:"failure_policy"`
	LogDir           string  `yaml:"log_dir" json:"log_dir"`
}

type Reviewer struct {
	Name     string
	Endpoint string
	APIKey   string
	Model    string
	Timeout  time.Duration
}

func DefaultConfig() Config {
	return Config{Enabled: true, PrimaryMode: "cpa", PrimaryTimeout: "10s", FallbackTimeout: "10s", Threshold: 80, FailurePolicy: "deny", LogDir: "./logs/llm-moderation"}
}

func ParseConfig(raw []byte) (Config, error) {
	c := DefaultConfig()
	if len(bytes.TrimSpace(raw)) != 0 {
		if err := yaml.Unmarshal(raw, &c); err != nil {
			return c, errors.New("invalid configuration syntax")
		}
	}
	c.PrimaryMode = strings.TrimSpace(c.PrimaryMode)
	c.CPABaseURL = strings.TrimRight(strings.TrimSpace(c.CPABaseURL), "/")
	c.PrimaryEndpoint = strings.TrimSpace(c.PrimaryEndpoint)
	c.FallbackEndpoint = strings.TrimSpace(c.FallbackEndpoint)
	c.PrimaryModel = strings.TrimSpace(c.PrimaryModel)
	c.FallbackModel = strings.TrimSpace(c.FallbackModel)
	return c, c.Validate()
}

func (c Config) Validate() error {
	if c.PrimaryMode != "cpa" && c.PrimaryMode != "external" {
		return errors.New("primary_mode must be cpa or external")
	}
	if math.IsNaN(c.Threshold) || math.IsInf(c.Threshold, 0) || c.Threshold < 0 || c.Threshold > 100 {
		return errors.New("threshold must be between 0 and 100")
	}
	if c.FailurePolicy != "deny" && c.FailurePolicy != "allow" {
		return errors.New("failure_policy must be deny or allow")
	}
	for _, v := range []string{c.PrimaryTimeout, c.FallbackTimeout} {
		d, err := time.ParseDuration(v)
		if err != nil || d < time.Millisecond || d > 5*time.Minute {
			return errors.New("timeouts must be between 1ms and 5m")
		}
	}
	if strings.TrimSpace(c.LogDir) == "" {
		return errors.New("log_dir is required")
	}
	if !c.Enabled || c.Threshold == 0 {
		return nil
	}
	if c.PrimaryModel == "" {
		return errors.New("primary_model is required")
	}
	if c.PrimaryMode == "cpa" {
		if err := validURL(c.CPABaseURL, false); err != nil {
			return fmt.Errorf("cpa_base_url: %w", err)
		}
		if strings.TrimSpace(c.CPAAPIKey) == "" {
			return errors.New("cpa_api_key is required")
		}
	} else if err := validURL(c.PrimaryEndpoint, true); err != nil {
		return fmt.Errorf("primary_endpoint: %w", err)
	}
	if c.FallbackEnabled {
		if c.FallbackModel == "" {
			return errors.New("fallback_model is required")
		}
		if err := validURL(c.FallbackEndpoint, true); err != nil {
			return fmt.Errorf("fallback_endpoint: %w", err)
		}
	}
	return nil
}

func validURL(raw string, chat bool) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.Fragment != "" {
		return errors.New("an absolute HTTP or HTTPS URL without user info or fragment is required")
	}
	if chat && !strings.HasSuffix(strings.TrimRight(u.Path, "/"), "/chat/completions") {
		return errors.New("endpoint must end with /chat/completions")
	}
	if !chat && u.RawQuery != "" {
		return errors.New("base URL must not contain a query")
	}
	return nil
}

func (c Config) Primary() Reviewer {
	d, _ := time.ParseDuration(c.PrimaryTimeout)
	r := Reviewer{Name: "primary", Endpoint: c.PrimaryEndpoint, APIKey: c.PrimaryAPIKey, Model: c.PrimaryModel, Timeout: d}
	if c.PrimaryMode == "cpa" {
		r.Endpoint, r.APIKey = c.CPAURL("chat/completions"), c.CPAAPIKey
	}
	return r
}

func (c Config) Fallback() Reviewer {
	d, _ := time.ParseDuration(c.FallbackTimeout)
	return Reviewer{Name: "fallback", Endpoint: c.FallbackEndpoint, APIKey: c.FallbackAPIKey, Model: c.FallbackModel, Timeout: d}
}

func (c Config) CPAURL(path string) string {
	base := strings.TrimRight(c.CPABaseURL, "/")
	if !strings.HasSuffix(base, "/v1") {
		base += "/v1"
	}
	return base + "/" + path
}

func (c Config) Secrets() []string {
	return []string{c.CPAAPIKey, c.PrimaryAPIKey, c.FallbackAPIKey}
}
