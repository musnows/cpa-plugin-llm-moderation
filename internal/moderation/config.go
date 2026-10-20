package moderation

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"net/url"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const ID = "llm-moderation"
const Version = "0.1.1"
const MaxInputBytes = 4 << 20
const MaxRequestBytes = 32 << 20
const MaxResponseBytes = 1 << 20
const MinTimeoutSeconds = 2
const MaxTimeoutSeconds = 600

type Config struct {
	Enabled          bool    `yaml:"enabled" json:"enabled"`
	PrimaryMode      string  `yaml:"primary_mode" json:"primary_mode"`
	CPABaseURL       string  `yaml:"cpa_base_url" json:"cpa_base_url"`
	CPAAPIKey        string  `yaml:"cpa_api_key" json:"cpa_api_key"`
	PrimaryEndpoint  string  `yaml:"primary_endpoint" json:"primary_endpoint"`
	PrimaryAPIKey    string  `yaml:"primary_api_key" json:"primary_api_key"`
	PrimaryModel     string  `yaml:"primary_model" json:"primary_model"`
	PrimaryTimeout   float64 `yaml:"primary_timeout" json:"primary_timeout"`
	FallbackEnabled  bool    `yaml:"fallback_enabled" json:"fallback_enabled"`
	FallbackMode     string  `yaml:"fallback_mode" json:"fallback_mode"`
	FallbackCPAURL   string  `yaml:"fallback_cpa_base_url" json:"fallback_cpa_base_url"`
	FallbackCPAKey   string  `yaml:"fallback_cpa_api_key" json:"fallback_cpa_api_key"`
	FallbackEndpoint string  `yaml:"fallback_endpoint" json:"fallback_endpoint"`
	FallbackAPIKey   string  `yaml:"fallback_api_key" json:"fallback_api_key"`
	FallbackModel    string  `yaml:"fallback_model" json:"fallback_model"`
	FallbackTimeout  float64 `yaml:"fallback_timeout" json:"fallback_timeout"`
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
	return Config{Enabled: true, PrimaryMode: "cpa", PrimaryTimeout: 10, FallbackMode: "external", FallbackTimeout: 10, Threshold: 80, FailurePolicy: "deny", LogDir: "./logs/llm-moderation"}
}

func ParseConfig(raw []byte) (Config, error) {
	c, err := ReadConfig(raw)
	if err != nil {
		return c, err
	}
	return c, c.Validate()
}

// ReadConfig accepts legacy duration strings when loading an existing installation.
func ReadConfig(raw []byte) (Config, error) {
	return decodeConfig(raw, true)
}

// ParseConfigWrite only accepts numeric seconds for new configuration writes.
func ParseConfigWrite(raw []byte) (Config, error) {
	c, err := decodeConfig(raw, false)
	if err != nil {
		return c, err
	}
	return c, c.Validate()
}

func decodeConfig(raw []byte, allowLegacy bool) (Config, error) {
	c := DefaultConfig()
	if len(bytes.TrimSpace(raw)) != 0 {
		var document yaml.Node
		if err := yaml.Unmarshal(raw, &document); err != nil || len(document.Content) != 1 || document.Content[0].Kind != yaml.MappingNode {
			return c, errors.New("invalid configuration syntax")
		}
		fields := document.Content[0].Content
		for i := 0; i < len(fields); i += 2 {
			name, value := fields[i].Value, fields[i+1]
			if name != "primary_timeout" && name != "fallback_timeout" {
				continue
			}
			if allowLegacy && value.Kind == yaml.ScalarNode && value.Tag == "!!str" {
				duration, err := time.ParseDuration(strings.TrimSpace(value.Value))
				if err != nil {
					return c, fmt.Errorf("%s must be a number of seconds between 2 and 600", name)
				}
				value.Tag, value.Value = "!!float", strconv.FormatFloat(duration.Seconds(), 'f', -1, 64)
			}
			if value.Kind != yaml.ScalarNode || (value.Tag != "!!int" && value.Tag != "!!float") {
				return c, fmt.Errorf("%s must be a number of seconds between 2 and 600", name)
			}
			var seconds float64
			if err := value.Decode(&seconds); err != nil || math.IsNaN(seconds) || math.IsInf(seconds, 0) {
				return c, fmt.Errorf("%s must be a number of seconds between 2 and 600", name)
			}
		}
		if err := document.Decode(&c); err != nil {
			return c, errors.New("invalid configuration syntax")
		}
	}
	c.PrimaryMode = strings.TrimSpace(c.PrimaryMode)
	c.FallbackMode = strings.TrimSpace(c.FallbackMode)
	c.CPABaseURL = strings.TrimRight(strings.TrimSpace(c.CPABaseURL), "/")
	c.FallbackCPAURL = strings.TrimRight(strings.TrimSpace(c.FallbackCPAURL), "/")
	c.PrimaryEndpoint = strings.TrimSpace(c.PrimaryEndpoint)
	c.FallbackEndpoint = strings.TrimSpace(c.FallbackEndpoint)
	c.PrimaryModel = strings.TrimSpace(c.PrimaryModel)
	c.FallbackModel = strings.TrimSpace(c.FallbackModel)
	return c, nil
}

func (c Config) Validate() error {
	if c.PrimaryMode != "cpa" && c.PrimaryMode != "external" {
		return errors.New("primary_mode must be cpa or external")
	}
	if c.FallbackMode != "cpa" && c.FallbackMode != "external" {
		return errors.New("fallback_mode must be cpa or external")
	}
	if math.IsNaN(c.Threshold) || math.IsInf(c.Threshold, 0) || c.Threshold < 0 || c.Threshold > 100 {
		return errors.New("threshold must be between 0 and 100")
	}
	if c.FailurePolicy != "deny" && c.FailurePolicy != "allow" {
		return errors.New("failure_policy must be deny or allow")
	}
	for _, timeout := range []struct {
		name    string
		seconds float64
	}{{"primary_timeout", c.PrimaryTimeout}, {"fallback_timeout", c.FallbackTimeout}} {
		if math.IsNaN(timeout.seconds) || math.IsInf(timeout.seconds, 0) || timeout.seconds < MinTimeoutSeconds || timeout.seconds > MaxTimeoutSeconds {
			return fmt.Errorf("%s must be a number of seconds between 2 and 600", timeout.name)
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
		if c.FallbackMode == "cpa" {
			if err := validURL(c.FallbackCPAURL, false); err != nil {
				return fmt.Errorf("fallback_cpa_base_url: %w", err)
			}
			if strings.TrimSpace(c.FallbackCPAKey) == "" {
				return errors.New("fallback_cpa_api_key is required")
			}
		} else if err := validURL(c.FallbackEndpoint, true); err != nil {
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
	d := time.Duration(c.PrimaryTimeout * float64(time.Second))
	r := Reviewer{Name: "primary", Endpoint: c.PrimaryEndpoint, APIKey: c.PrimaryAPIKey, Model: c.PrimaryModel, Timeout: d}
	if c.PrimaryMode == "cpa" {
		r.Endpoint, r.APIKey = c.CPAURL("chat/completions"), c.CPAAPIKey
	}
	return r
}

func (c Config) Fallback() Reviewer {
	d := time.Duration(c.FallbackTimeout * float64(time.Second))
	r := Reviewer{Name: "fallback", Endpoint: c.FallbackEndpoint, APIKey: c.FallbackAPIKey, Model: c.FallbackModel, Timeout: d}
	if c.FallbackMode == "cpa" {
		r.Endpoint, r.APIKey = cpaURL(c.FallbackCPAURL, "chat/completions"), c.FallbackCPAKey
	}
	return r
}

func (c Config) CPAURL(path string) string {
	return cpaURL(c.CPABaseURL, path)
}

func cpaURL(baseURL, path string) string {
	base := strings.TrimRight(baseURL, "/")
	if !strings.HasSuffix(base, "/v1") {
		base += "/v1"
	}
	return base + "/" + path
}

func (c Config) Secrets() []string {
	return []string{c.CPAAPIKey, c.PrimaryAPIKey, c.FallbackAPIKey, c.FallbackCPAKey}
}
