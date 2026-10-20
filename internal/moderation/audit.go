package moderation

import (
	"bufio"
	"container/heap"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type Attempt struct {
	Reviewer   string  `json:"reviewer"`
	Model      string  `json:"model"`
	Outcome    string  `json:"outcome"`
	HTTPStatus int     `json:"http_status"`
	DurationMS float64 `json:"duration_ms"`
	ErrorCode  string  `json:"error_code,omitempty"`
}

type Record struct {
	Time               time.Time `json:"time"`
	RequestID          string    `json:"request_id"`
	TraceID            string    `json:"trace_id"`
	Protocol           string    `json:"protocol"`
	TargetModel        string    `json:"target_model"`
	RequestedModel     string    `json:"requested_model"`
	KeyFingerprint     string    `json:"key_fingerprint"`
	MaskedKey          string    `json:"masked_key"`
	IsViolation        *bool     `json:"is_violation"`
	Confidence         *float64  `json:"confidence"`
	Categories         []string  `json:"categories"`
	Reason             string    `json:"reason"`
	Threshold          float64   `json:"threshold"`
	Decision           string    `json:"decision"`
	DecisionStatus     int       `json:"decision_status"`
	ErrorCode          string    `json:"error_code,omitempty"`
	FinalReviewer      string    `json:"final_reviewer"`
	FinalReviewModel   string    `json:"final_review_model"`
	FallbackUsed       bool      `json:"fallback_used"`
	PrimaryDurationMS  float64   `json:"primary_duration_ms"`
	FallbackDurationMS float64   `json:"fallback_duration_ms"`
	ReviewTotalMS      float64   `json:"review_total_ms"`
	PrecheckDurationMS float64   `json:"precheck_duration_ms"`
	Attempts           []Attempt `json:"attempts"`
	PromptVersion      string    `json:"prompt_version"`
	PromptMode         string    `json:"prompt_mode,omitempty"`
	PromptSHA256       string    `json:"prompt_sha256,omitempty"`
}

type Sink interface{ Append(Record) error }

type FileStore struct {
	Dir string
	mu  sync.Mutex
}

func NewFileStore(dir string) *FileStore { return &FileStore{Dir: dir} }

func (s *FileStore) Append(record Record) error {
	raw, err := json.Marshal(record)
	if err != nil {
		return errors.New("audit_record_encoding_failed")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.MkdirAll(s.Dir, 0700); err != nil {
		return errors.New("audit_directory_unavailable")
	}
	file, err := os.OpenFile(filepath.Join(s.Dir, record.Time.UTC().Format("2006-01-02")+".jsonl"), os.O_CREATE|os.O_APPEND|os.O_RDWR, 0600)
	if err != nil {
		return errors.New("audit_log_open_failed")
	}
	defer file.Close()
	if info, err := file.Stat(); err == nil && info.Size() > 0 {
		var tail [1]byte
		if _, err := file.ReadAt(tail[:], info.Size()-1); err != nil {
			return errors.New("audit_log_read_failed")
		}
		if tail[0] != '\n' {
			if _, err := file.Write([]byte{'\n'}); err != nil {
				return errors.New("audit_log_write_failed")
			}
		}
	}
	if _, err := file.Write(append(raw, '\n')); err != nil {
		return errors.New("audit_log_write_failed")
	}
	return nil
}

type Filter struct {
	From        time.Time
	To          time.Time
	Key         string
	TargetModel string
	ReviewModel string
	Decision    string
	Cursor      string
	Limit       int
}

type Page struct {
	Records      []Record `json:"records"`
	NextCursor   string   `json:"next_cursor"`
	CorruptLines int      `json:"corrupt_lines"`
}

func recordKey(r Record) string {
	return r.Time.UTC().Format("2006-01-02T15:04:05.000000000Z") + "|" + r.RequestID
}

func (f Filter) match(r Record) bool {
	if r.Time.Before(f.From) || r.Time.After(f.To) {
		return false
	}
	if f.Key != "" && !strings.Contains(r.KeyFingerprint, f.Key) && !strings.Contains(r.MaskedKey, f.Key) {
		return false
	}
	if f.TargetModel != "" && r.TargetModel != f.TargetModel && r.RequestedModel != f.TargetModel {
		return false
	}
	if f.ReviewModel != "" {
		found := false
		for _, a := range r.Attempts {
			if a.Model == f.ReviewModel {
				found = true
			}
		}
		if !found {
			return false
		}
	}
	return f.Decision == "" || r.Decision == f.Decision
}

func (s *FileStore) scan(f Filter, visit func(Record)) (int, error) {
	if f.From.IsZero() || f.To.Before(f.From) || f.To.Sub(f.From) > 31*24*time.Hour {
		return 0, errors.New("time_range_must_be_between_zero_and_31_days")
	}
	entries, err := os.ReadDir(s.Dir)
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, errors.New("audit_directory_unavailable")
	}
	corrupt := 0
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".jsonl") {
			continue
		}
		date, err := time.Parse("2006-01-02.jsonl", entry.Name())
		if err != nil || date.Add(24*time.Hour).Before(f.From) || date.After(f.To) {
			continue
		}
		file, err := os.Open(filepath.Join(s.Dir, entry.Name()))
		if err != nil {
			return corrupt, errors.New("audit_log_read_failed")
		}
		reader := bufio.NewReader(file)
		for {
			raw, oversized, errRead := readAuditLine(reader)
			if errRead != nil && errRead != io.EOF {
				file.Close()
				return corrupt, errors.New("audit_log_read_failed")
			}
			if len(raw) > 0 || oversized {
				var r Record
				if oversized || len(raw) == 0 || raw[len(raw)-1] != '\n' || json.Unmarshal(raw, &r) != nil || r.Time.IsZero() || r.RequestID == "" {
					corrupt++
				} else if f.match(r) {
					visit(r)
				}
			}
			if errRead == io.EOF {
				break
			}
		}
		file.Close()
	}
	return corrupt, nil
}

func readAuditLine(reader *bufio.Reader) ([]byte, bool, error) {
	var raw []byte
	oversized := false
	for {
		part, err := reader.ReadSlice('\n')
		if len(raw)+len(part) > MaxResponseBytes {
			oversized = true
		}
		if !oversized {
			raw = append(raw, part...)
		}
		if err != bufio.ErrBufferFull {
			return raw, oversized, err
		}
	}
}

type recordHeap []Record

func (h recordHeap) Len() int           { return len(h) }
func (h recordHeap) Less(i, j int) bool { return recordKey(h[i]) < recordKey(h[j]) }
func (h recordHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *recordHeap) Push(v any)        { *h = append(*h, v.(Record)) }
func (h *recordHeap) Pop() any          { old := *h; v := old[len(old)-1]; *h = old[:len(old)-1]; return v }

func (s *FileStore) Records(f Filter) (Page, error) {
	if f.Limit <= 0 {
		f.Limit = 50
	}
	if f.Limit > 200 {
		f.Limit = 200
	}
	var cursor string
	if f.Cursor != "" {
		raw, err := base64.RawURLEncoding.DecodeString(f.Cursor)
		if err != nil || len(raw) > 512 {
			return Page{}, errors.New("invalid_cursor")
		}
		cursor = string(raw)
	}
	h := &recordHeap{}
	corrupt, err := s.scan(f, func(r Record) {
		if cursor != "" && recordKey(r) >= cursor {
			return
		}
		heap.Push(h, r)
		if h.Len() > f.Limit+1 {
			heap.Pop(h)
		}
	})
	if err != nil {
		return Page{}, err
	}
	records := []Record(*h)
	sort.Slice(records, func(i, j int) bool { return recordKey(records[i]) > recordKey(records[j]) })
	page := Page{Records: records, CorruptLines: corrupt}
	if len(records) > f.Limit {
		page.Records = records[:f.Limit]
		page.NextCursor = base64.RawURLEncoding.EncodeToString([]byte(recordKey(page.Records[len(page.Records)-1])))
	}
	if page.Records == nil {
		page.Records = []Record{}
	}
	return page, nil
}

type Durations struct {
	Count int     `json:"count"`
	P50MS float64 `json:"p50_ms"`
	P95MS float64 `json:"p95_ms"`
	AvgMS float64 `json:"avg_ms"`
}
type histogram struct {
	buckets map[int]int
	count   int
	sum     float64
}

func (h *histogram) add(v float64) {
	if math.IsNaN(v) || math.IsInf(v, 0) || v < 0 {
		return
	}
	if h.buckets == nil {
		h.buckets = map[int]int{}
	}
	bucket := min(int(math.Round(v)), 2*MaxTimeoutSeconds*1000)
	h.buckets[bucket]++
	h.count++
	h.sum += v
}
func (h *histogram) result() Durations {
	if h.count == 0 {
		return Durations{}
	}
	keys := make([]int, 0, len(h.buckets))
	for key := range h.buckets {
		keys = append(keys, key)
	}
	sort.Ints(keys)
	percentile := func(p float64) float64 {
		goal, seen := int(math.Ceil(float64(h.count)*p)), 0
		for _, key := range keys {
			seen += h.buckets[key]
			if seen >= goal {
				return float64(key)
			}
		}
		return 0
	}
	return Durations{Count: h.count, P50MS: percentile(.5), P95MS: percentile(.95), AvgMS: h.sum / float64(h.count)}
}

type Summary struct {
	Requests     int       `json:"requests"`
	Blocked      int       `json:"blocked"`
	Failures     int       `json:"failures"`
	Fallbacks    int       `json:"fallbacks"`
	BlockRate    float64   `json:"block_rate"`
	FailureRate  float64   `json:"failure_rate"`
	FallbackRate float64   `json:"fallback_rate"`
	Primary      Durations `json:"primary"`
	Fallback     Durations `json:"fallback"`
	Precheck     Durations `json:"precheck"`
	CorruptLines int       `json:"corrupt_lines"`
}

func (s *FileStore) Summary(f Filter) (Summary, error) {
	var summary Summary
	var primary, fallback, precheck histogram
	corrupt, err := s.scan(f, func(r Record) {
		summary.Requests++
		if r.Decision == "block" {
			summary.Blocked++
		}
		if strings.HasPrefix(r.Decision, "error_") || r.Decision == "canceled" {
			summary.Failures++
		}
		if r.FallbackUsed {
			summary.Fallbacks++
		}
		for _, a := range r.Attempts {
			if a.Reviewer == "primary" {
				primary.add(a.DurationMS)
			} else {
				fallback.add(a.DurationMS)
			}
		}
		precheck.add(r.PrecheckDurationMS)
	})
	summary.CorruptLines = corrupt
	summary.Primary, summary.Fallback, summary.Precheck = primary.result(), fallback.result(), precheck.result()
	if summary.Requests > 0 {
		n := float64(summary.Requests)
		summary.BlockRate = float64(summary.Blocked) / n
		summary.FailureRate = float64(summary.Failures) / n
		summary.FallbackRate = float64(summary.Fallbacks) / n
	}
	return summary, err
}
