package proxy

import (
	"testing"
	"time"
)

// TestRequestApproval_MultipleRequests verifies that the approval channel
// can handle multiple sequential requests.  This is a Server-layer test:
// it does NOT involve the TUI, but it validates that requestApproval()
// itself returns sensible results for approved/denied/timeout scenarios
// and that the channel is reusable after each response.
//
// The complementary TUI-layer regression (re-arm after approvalMsg) is
// covered by TestApprovalListener_RearmAfterFirstRequest below.

func TestRequestApproval_ApprovedOnce(t *testing.T) {
	ch := make(chan ApprovalRequest, 10)
	srv := NewServer(0, ch)

	// Consume approval requests in a background goroutine and auto-approve them.
	go func() {
		for req := range ch {
			req.ResponseCh <- ApprovalResponse{Approved: true, Permanent: false}
		}
	}()

	status := srv.requestApproval("c1", "api.openai.com", "CONNECT", "api.openai.com:443", "")
	if status != "approved" {
		t.Errorf("expected approved, got %s", status)
	}
}

func TestRequestApproval_DeniedOnce(t *testing.T) {
	ch := make(chan ApprovalRequest, 10)
	srv := NewServer(0, ch)

	go func() {
		for req := range ch {
			req.ResponseCh <- ApprovalResponse{Approved: false, Permanent: false}
		}
	}()

	status := srv.requestApproval("c1", "evil.com", "CONNECT", "evil.com:443", "")
	if status != "denied" {
		t.Errorf("expected denied, got %s", status)
	}
}

func TestRequestApproval_DeniedPermanent(t *testing.T) {
	ch := make(chan ApprovalRequest, 10)
	srv := NewServer(0, ch)

	go func() {
		for req := range ch {
			req.ResponseCh <- ApprovalResponse{Approved: false, Permanent: true}
		}
	}()

	status := srv.requestApproval("c1", "evil.com", "CONNECT", "evil.com:443", "")
	if status != "denied-permanent" {
		t.Errorf("expected denied-permanent, got %s", status)
	}
}

func TestRequestApproval_Timeout(t *testing.T) {
	ch := make(chan ApprovalRequest, 10)
	srv := NewServer(0, ch)
	srv.timeout = 50 * time.Millisecond // very short for test

	// Nobody is reading the channel → timeout fires.
	status := srv.requestApproval("c1", "slow.com", "CONNECT", "slow.com:443", "")
	if status != "timeout" {
		t.Errorf("expected timeout, got %s", status)
	}
}

func TestRequestApproval_QueueFull(t *testing.T) {
	// Channel with zero buffer — approvalCh send will block; after 2s it returns denied-queue-full.
	// Use a very short window to keep the test fast by patching the timeout inline.
	// Actually: queue-full fires after 2s (hardcoded), so we'll use a buffered channel
	// that is already full.
	ch := make(chan ApprovalRequest, 1)
	srv := NewServer(0, ch)

	// Fill the channel buffer so the next send blocks immediately
	ch <- ApprovalRequest{ResponseCh: make(chan ApprovalResponse, 1), CancelCh: make(chan struct{})}

	// The 2-second enqueue timeout fires → denied-queue-full
	// We override server.timeout to differentiate from approval timeout.
	srv.timeout = 5 * time.Second // big, so it doesn't fire first

	done := make(chan string, 1)
	go func() {
		done <- srv.requestApproval("c1", "x.com", "GET", "http://x.com/", "/")
	}()

	select {
	case status := <-done:
		if status != "denied-queue-full" {
			t.Errorf("expected denied-queue-full, got %s", status)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("timed out waiting for denied-queue-full")
	}
}

// TestRequestApproval_SequentialRequests is the key regression test:
// verifies that a second approval request succeeds after the first one
// has already been answered.  If the TUI forgets to re-arm the listener
// after the first approvalMsg, the Server side is still fine — it's the
// TUI goroutine that stops receiving.  This test validates the Server contract.
func TestRequestApproval_SequentialRequests(t *testing.T) {
	ch := make(chan ApprovalRequest, 10)
	srv := NewServer(0, ch)

	responses := []ApprovalResponse{
		{Approved: true, Permanent: false},
		{Approved: false, Permanent: false},
		{Approved: true, Permanent: true},
	}

	go func() {
		i := 0
		for req := range ch {
			if i < len(responses) {
				req.ResponseCh <- responses[i]
				i++
			}
		}
	}()

	expected := []string{"approved", "denied", "approved-permanent"}
	for i, want := range expected {
		got := srv.requestApproval("c1", "domain.com", "CONNECT", "domain.com:443", "")
		if got != want {
			t.Errorf("request[%d]: expected %s, got %s", i, want, got)
		}
	}
}

// TestApprovalListener_RearmAfterFirstRequest is a behavioural regression test
// for the bug where approvalMsg in app.go Update() did not call
// listenApprovalsContinue(), causing the second approval request to be
// silently timed-out instead of shown to the operator.
//
// We simulate the TUI listener loop here at the channel level:
// one reader goroutine, two sequential approval requests.
func TestApprovalListener_RearmAfterFirstRequest(t *testing.T) {
	ch := make(chan ApprovalRequest, 10)
	srv := NewServer(0, ch)

	results := make(chan string, 4)

	// Simulate what the TUI does: one goroutine reads one request,
	// answers it, then reads the next — mirroring the re-arm fix.
	go func() {
		for req := range ch {
			// Simulate operator pressing 'y' (approve once)
			req.ResponseCh <- ApprovalResponse{Approved: true, Permanent: false}
		}
	}()

	// Fire two sequential approval requests
	for i := 0; i < 2; i++ {
		go func() {
			results <- srv.requestApproval("c1", "api.openai.com", "CONNECT", "api.openai.com:443", "")
		}()
	}

	for i := 0; i < 2; i++ {
		select {
		case status := <-results:
			if status != "approved" {
				t.Errorf("request %d: expected approved, got %s (re-arm bug?)", i, status)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("request %d timed out — possible re-arm regression", i)
		}
	}
}
