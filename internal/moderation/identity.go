package moderation

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"
)

const InternalHeader = "X-CPA-Moderation-Nonce"

func CallerFingerprint(key string) string {
	key = strings.TrimSpace(key)
	if key == "" {
		return ""
	}
	sum := sha256.Sum256([]byte("cli-proxy-api:caller-scope:v1\x00" + key))
	return hex.EncodeToString(sum[:])
}

func HeaderKeys(h http.Header) []string {
	var keys []string
	if fields := strings.Fields(h.Get("Authorization")); len(fields) == 2 && strings.EqualFold(fields[0], "Bearer") {
		keys = append(keys, fields[1])
	}
	for _, name := range []string{"X-Api-Key", "X-Goog-Api-Key"} {
		if key := strings.TrimSpace(h.Get(name)); key != "" {
			keys = append(keys, key)
		}
	}
	return keys
}

func Identify(headers http.Header, metadata map[string]any) (string, string) {
	scope, _ := metadata["caller_scope"].(string)
	for _, key := range HeaderKeys(headers) {
		if scope != "" && CallerFingerprint(key) == scope {
			if len(key) < 12 {
				return scope, "[redacted]"
			}
			return scope, key[:4] + "..." + key[len(key)-4:]
		}
	}
	if scope == "" {
		scope = "unidentified"
	}
	return scope, "unavailable"
}

type nonceEntry struct {
	Digest [32]byte
	Caller string
	Expiry time.Time
}

type Nonces struct {
	mu      sync.Mutex
	entries map[string]nonceEntry
}

func NewNonces() *Nonces { return &Nonces{entries: map[string]nonceEntry{}} }

func payloadDigest(body []byte) ([32]byte, error) {
	var value any
	if err := DecodeJSON(body, &value); err != nil {
		return [32]byte{}, err
	}
	canonical, err := json.Marshal(value)
	return sha256.Sum256(canonical), err
}

func (n *Nonces) Issue(body []byte, apiKey string, ttl time.Duration) (string, error) {
	digest, err := payloadDigest(body)
	if err != nil {
		return "", err
	}
	var random [32]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", errors.New("nonce_generation_failed")
	}
	now := time.Now()
	n.mu.Lock()
	defer n.mu.Unlock()
	for key, value := range n.entries {
		if now.After(value.Expiry) {
			delete(n.entries, key)
		}
	}
	if len(n.entries) >= 4096 {
		return "", errors.New("review_concurrency_limit")
	}
	token := hex.EncodeToString(random[:])
	n.entries[token] = nonceEntry{Digest: digest, Caller: CallerFingerprint(apiKey), Expiry: now.Add(ttl)}
	return token, nil
}

func (n *Nonces) Forget(token string) {
	n.mu.Lock()
	delete(n.entries, token)
	n.mu.Unlock()
}

func (n *Nonces) Consume(token string, body []byte, metadata map[string]any) bool {
	if token == "" {
		return false
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	entry, ok := n.entries[token]
	if !ok || time.Now().After(entry.Expiry) {
		delete(n.entries, token)
		return false
	}
	scope, _ := metadata["caller_scope"].(string)
	if scope != entry.Caller {
		return false
	}
	digest, err := payloadDigest(body)
	if err != nil || digest != entry.Digest {
		return false
	}
	delete(n.entries, token)
	return true
}

func redact(value string, secrets []string) string {
	for _, secret := range secrets {
		if len(secret) >= 4 {
			value = strings.ReplaceAll(value, secret, "[redacted]")
		}
	}
	return value
}
