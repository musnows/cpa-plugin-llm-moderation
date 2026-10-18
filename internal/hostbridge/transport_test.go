package hostbridge

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/musnows/cpa-plugin-llm-moderation/internal/moderation"
	"sync"
	"testing"
	"time"
)

func TestHostCancellationJoinsRequest(t *testing.T) {
	started, finished, canceled := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once sync.Once
	transport := &Transport{Call: func(method string, input any, output any) error {
		switch method {
		case "host.http.operation_open":
			return json.Unmarshal([]byte(`{"operation_id":"op-1"}`), output)
		case "host.http.do":
			close(started)
			<-canceled
			close(finished)
			return errors.New("context canceled")
		case "host.http.cancel":
			once.Do(func() { close(canceled) })
			return nil
		}
		t.Fatal("unexpected method")
		return nil
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Millisecond)
	defer cancel()
	_, err := transport.Do(ctx, "scope", moderation.HTTPRequest{})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("got %v", err)
	}
	select {
	case <-started:
	default:
		t.Fatal("request never started")
	}
	select {
	case <-finished:
	default:
		t.Fatal("request left running after timeout")
	}
}
func TestHostParentCancellation(t *testing.T) {
	transport := &Transport{Call: func(method string, input any, output any) error {
		if method == "host.http.operation_open" {
			return json.Unmarshal([]byte(`{"operation_id":"x"}`), output)
		}
		if method == "host.http.do" {
			return errors.New("upstream: context canceled")
		}
		return nil
	}}
	_, err := transport.Do(context.Background(), "scope", moderation.HTTPRequest{})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("parent cancellation lost: %v", err)
	}
}
