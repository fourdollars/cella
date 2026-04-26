package proxy

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// ── ParseInferenceRequest ──

func TestParseInferenceRequest_OpenAI(t *testing.T) {
	body := []byte(`{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}`)
	model := ParseInferenceRequest(body)
	if model != "gpt-4o" {
		t.Errorf("ParseInferenceRequest = %q, want %q", model, "gpt-4o")
	}
}

func TestParseInferenceRequest_Anthropic(t *testing.T) {
	body := []byte(`{"model":"claude-sonnet-4-5","max_tokens":1024,"messages":[]}`)
	model := ParseInferenceRequest(body)
	if model != "claude-sonnet-4-5" {
		t.Errorf("ParseInferenceRequest = %q, want %q", model, "claude-sonnet-4-5")
	}
}

func TestParseInferenceRequest_Empty(t *testing.T) {
	model := ParseInferenceRequest([]byte(`{}`))
	if model != "" {
		t.Errorf("ParseInferenceRequest empty body = %q, want empty", model)
	}
}

func TestParseInferenceRequest_Invalid(t *testing.T) {
	model := ParseInferenceRequest([]byte(`not json`))
	if model != "" {
		t.Errorf("ParseInferenceRequest invalid JSON = %q, want empty", model)
	}
}

// ── ParseInferenceResponse ──

func TestParseInferenceResponse_OpenAI(t *testing.T) {
	body := []byte(`{
		"model": "gpt-4o",
		"usage": {"prompt_tokens": 100, "completion_tokens": 50}
	}`)
	model, in, out := ParseInferenceResponse(body)
	if model != "gpt-4o" {
		t.Errorf("model = %q, want gpt-4o", model)
	}
	if in != 100 {
		t.Errorf("tokensIn = %d, want 100", in)
	}
	if out != 50 {
		t.Errorf("tokensOut = %d, want 50", out)
	}
}

func TestParseInferenceResponse_Anthropic(t *testing.T) {
	body := []byte(`{
		"model": "claude-sonnet-4-5",
		"usage": {"input_tokens": 200, "output_tokens": 80}
	}`)
	model, in, out := ParseInferenceResponse(body)
	if model != "claude-sonnet-4-5" {
		t.Errorf("model = %q", model)
	}
	if in != 200 || out != 80 {
		t.Errorf("tokens = (%d, %d), want (200, 80)", in, out)
	}
}

func TestParseInferenceResponse_CopilotTotalOnly(t *testing.T) {
	body := []byte(`{
		"model": "github-copilot/gpt-5-mini",
		"usage": {"total_tokens": 300}
	}`)
	model, in, out := ParseInferenceResponse(body)
	if model != "github-copilot/gpt-5-mini" {
		t.Errorf("model = %q", model)
	}
	if in+out != 300 {
		t.Errorf("total tokens = %d, want 300", in+out)
	}
}

func TestParseInferenceResponse_Empty(t *testing.T) {
	model, in, out := ParseInferenceResponse([]byte(`{}`))
	if model != "" || in != 0 || out != 0 {
		t.Errorf("empty body should return zero values, got (%q,%d,%d)", model, in, out)
	}
}

// ── ParseSSETokens ──

func makeSSE(chunks []string) []byte {
	var b strings.Builder
	for _, c := range chunks {
		b.WriteString("data: ")
		b.WriteString(c)
		b.WriteString("\n\n")
	}
	b.WriteString("data: [DONE]\n\n")
	return []byte(b.String())
}

func TestParseSSETokens_OpenAIStreaming(t *testing.T) {
	// OpenAI sends usage in the final chunk
	finalChunk := `{"model":"gpt-4o","choices":[],"usage":{"prompt_tokens":150,"completion_tokens":60}}`
	body := makeSSE([]string{
		`{"model":"gpt-4o","choices":[{"delta":{"content":"Hello"}}]}`,
		`{"model":"gpt-4o","choices":[{"delta":{"content":" world"}}]}`,
		finalChunk,
	})
	model, in, out := ParseSSETokens(body)
	if model != "gpt-4o" {
		t.Errorf("model = %q, want gpt-4o", model)
	}
	if in != 150 {
		t.Errorf("tokensIn = %d, want 150", in)
	}
	if out != 60 {
		t.Errorf("tokensOut = %d, want 60", out)
	}
}

func TestParseSSETokens_AnthropicStreaming(t *testing.T) {
	// Anthropic streams with input_tokens in message_start, output_tokens in message_delta
	body := makeSSE([]string{
		`{"type":"message_start","message":{"model":"claude-sonnet-4-5","usage":{"input_tokens":120,"output_tokens":0}}}`,
		`{"type":"content_block_delta","delta":{"text":"Hello"}}`,
		`{"type":"message_delta","usage":{"output_tokens":45}}`,
	})
	model, in, out := ParseSSETokens(body)
	// Model extracted from first chunk's nested message field — may be empty if not at top level
	// Input tokens from message_start
	if in != 120 {
		t.Errorf("tokensIn = %d, want 120", in)
	}
	if out != 45 {
		t.Errorf("tokensOut = %d, want 45", out)
	}
	_ = model // may be empty for Anthropic SSE (nested field)
}

func TestParseSSETokens_NoUsage(t *testing.T) {
	// Streaming response with no usage info
	body := makeSSE([]string{
		`{"model":"gpt-4o","choices":[{"delta":{"content":"hi"}}]}`,
	})
	model, in, out := ParseSSETokens(body)
	if model != "gpt-4o" {
		t.Errorf("model = %q, want gpt-4o", model)
	}
	if in != 0 || out != 0 {
		t.Errorf("tokens = (%d, %d), want (0, 0)", in, out)
	}
}

func TestParseSSETokens_Empty(t *testing.T) {
	model, in, out := ParseSSETokens([]byte(""))
	if model != "" || in != 0 || out != 0 {
		t.Errorf("empty SSE body should return zeros, got (%q,%d,%d)", model, in, out)
	}
}

// ── IsStreamingResponse ──

func TestIsStreamingResponse(t *testing.T) {
	cases := []struct {
		ct   string
		want bool
	}{
		{"text/event-stream", true},
		{"text/event-stream; charset=utf-8", true},
		{"TEXT/EVENT-STREAM", true},
		{"application/json", false},
		{"", false},
	}
	for _, c := range cases {
		got := IsStreamingResponse(c.ct)
		if got != c.want {
			t.Errorf("IsStreamingResponse(%q) = %v, want %v", c.ct, got, c.want)
		}
	}
}

// ── GetPricing / CalcCost / FormatCost ──

func TestGetPricing_ExactMatch(t *testing.T) {
	p, ok := GetPricing("gpt-4o")
	if !ok {
		t.Fatal("expected pricing for gpt-4o")
	}
	if p.InputPer1M != 2.50 {
		t.Errorf("InputPer1M = %f, want 2.50", p.InputPer1M)
	}
}

func TestGetPricing_FuzzyMatch(t *testing.T) {
	_, ok := GetPricing("openai/gpt-4o-mini")
	if !ok {
		t.Error("expected fuzzy match for openai/gpt-4o-mini")
	}
}

func TestGetPricing_Unknown(t *testing.T) {
	_, ok := GetPricing("totally-unknown-model-xyz")
	if ok {
		t.Error("expected no pricing for unknown model")
	}
}

func TestCalcCost_KnownModel(t *testing.T) {
	// gpt-4o: $2.50/1M in, $10.00/1M out
	cost := CalcCost("gpt-4o", 1_000_000, 500_000)
	expected := 2.50 + 5.00 // 1M in + 0.5M out
	if cost < expected-0.01 || cost > expected+0.01 {
		t.Errorf("CalcCost = %f, want ~%f", cost, expected)
	}
}

func TestCalcCost_UnknownModel(t *testing.T) {
	cost := CalcCost("mystery-model", 1_000_000, 1_000_000)
	if cost != 0 {
		t.Errorf("CalcCost unknown model = %f, want 0", cost)
	}
}

func TestFormatCost(t *testing.T) {
	cases := []struct {
		usd  float64
		want string
	}{
		{0.00001, "$0.0000"},
		{0.005, "$0.005"},
		{0.05, "$0.050"},
		{1.50, "$1.50"},
	}
	for _, c := range cases {
		got := FormatCost(c.usd)
		if got != c.want {
			t.Errorf("FormatCost(%f) = %q, want %q", c.usd, got, c.want)
		}
	}
}

func TestFormatTokens(t *testing.T) {
	cases := []struct {
		n    int64
		want string
	}{
		{500, "500"},
		{1500, "1.5K"},
		{1_500_000, "1.5M"},
	}
	for _, c := range cases {
		got := FormatTokens(c.n)
		if got != c.want {
			t.Errorf("FormatTokens(%d) = %q, want %q", c.n, got, c.want)
		}
	}
}

// ── InferenceStats.Record + GetModelStats ──

func TestInferenceStats_RecordAndQuery(t *testing.T) {
	s := NewInferenceStats()
	now := time.Now()
	s.Record(InferenceRequest{
		Time: now, Container: "agent1", Domain: "api.openai.com",
		Model: "gpt-4o", Path: "/v1/chat/completions",
		TokensIn: 100, TokensOut: 50, StatusCode: 200,
	})
	s.Record(InferenceRequest{
		Time: now, Container: "agent1", Domain: "api.openai.com",
		Model: "gpt-4o", Path: "/v1/chat/completions",
		TokensIn: 200, TokensOut: 80, StatusCode: 200,
	})

	stats := s.GetModelStats()
	if len(stats) != 1 {
		t.Fatalf("expected 1 model, got %d", len(stats))
	}
	ms := stats[0]
	if ms.Model != "gpt-4o" {
		t.Errorf("model = %q", ms.Model)
	}
	if ms.TotalRequests != 2 {
		t.Errorf("TotalRequests = %d, want 2", ms.TotalRequests)
	}
	if ms.TotalTokensIn != 300 {
		t.Errorf("TotalTokensIn = %d, want 300", ms.TotalTokensIn)
	}
	if ms.TotalTokensOut != 130 {
		t.Errorf("TotalTokensOut = %d, want 130", ms.TotalTokensOut)
	}
	if !ms.HasPricing {
		t.Error("expected HasPricing = true for gpt-4o")
	}
	if ms.Cost <= 0 {
		t.Error("expected positive Cost")
	}
}

func TestInferenceStats_TotalCostToday(t *testing.T) {
	s := NewInferenceStats()
	s.Record(InferenceRequest{
		Time: time.Now(), Model: "gpt-4o",
		TokensIn: 1_000_000, TokensOut: 0,
	})
	cost := s.TotalCostToday()
	if cost <= 0 {
		t.Errorf("TotalCostToday = %f, want > 0", cost)
	}
}

func TestInferenceStats_GetRecentRequests(t *testing.T) {
	s := NewInferenceStats()
	for i := 0; i < 5; i++ {
		s.Record(InferenceRequest{
			Time:  time.Now(),
			Model: fmt.Sprintf("model-%d", i),
		})
	}
	reqs := s.GetRecentRequests(3)
	if len(reqs) != 3 {
		t.Errorf("GetRecentRequests(3) = %d, want 3", len(reqs))
	}
	// Newest first — last recorded model should be first
	if reqs[0].Model != "model-4" {
		t.Errorf("reqs[0].Model = %q, want model-4", reqs[0].Model)
	}
}

// ── OpenAI Responses API (GitHub Copilot /responses) SSE ──

func TestParseSSETokens_CopilotResponsesAPI(t *testing.T) {
	// Simulates the GitHub Copilot /responses SSE stream.
	// The final event is "response.completed" which wraps model + usage under "response".
	body := []byte(
		"event: response.created\n" +
			"data: {\"type\":\"response.created\",\"response\":{\"id\":\"resp_abc\",\"model\":\"gpt-5-mini\",\"status\":\"in_progress\"}}\n\n" +
			"event: response.output_item.added\n" +
			"data: {\"type\":\"response.output_item.added\",\"output_index\":0,\"item\":{\"type\":\"message\",\"role\":\"assistant\"}}\n\n" +
			"event: response.content_part.added\n" +
			"data: {\"type\":\"response.content_part.added\",\"item_id\":\"msg_1\",\"output_index\":0,\"content_index\":0,\"part\":{\"type\":\"output_text\",\"text\":\"\"}}\n\n" +
			"event: response.output_text.delta\n" +
			"data: {\"type\":\"response.output_text.delta\",\"item_id\":\"msg_1\",\"output_index\":0,\"content_index\":0,\"delta\":\"Hello\"}\n\n" +
			"event: response.output_text.delta\n" +
			"data: {\"type\":\"response.output_text.delta\",\"item_id\":\"msg_1\",\"output_index\":0,\"content_index\":0,\"delta\":\" World\"}\n\n" +
			"event: response.completed\n" +
			"data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_abc\",\"model\":\"gpt-5-mini\",\"status\":\"completed\",\"usage\":{\"input_tokens\":25,\"output_tokens\":100,\"total_tokens\":125}}}\n\n",
	)
	model, in, out := ParseSSETokens(body)
	if model != "gpt-5-mini" {
		t.Errorf("model = %q, want gpt-5-mini", model)
	}
	if in != 25 {
		t.Errorf("tokensIn = %d, want 25", in)
	}
	if out != 100 {
		t.Errorf("tokensOut = %d, want 100", out)
	}
}

func TestParseSSETokens_CopilotResponsesAPI_TotalOnly(t *testing.T) {
	// Variant: only total_tokens provided (no breakdown) → split evenly
	body := []byte(
		"event: response.completed\n" +
			"data: {\"type\":\"response.completed\",\"response\":{\"model\":\"gpt-5-mini\",\"usage\":{\"total_tokens\":200}}}\n\n",
	)
	model, in, out := ParseSSETokens(body)
	if model != "gpt-5-mini" {
		t.Errorf("model = %q, want gpt-5-mini", model)
	}
	if in+out != 200 {
		t.Errorf("total tokens = %d, want 200", in+out)
	}
}

func TestGetPricing_NormalizedMatch(t *testing.T) {
	_, ok := GetPricing("claude-opus-4.6")
	if !ok {
		t.Error("expected normalized match for claude-opus-4.6 (against claude-opus-4-6)")
	}

	_, ok = GetPricing("gpt-5.3-codex")
	if !ok {
		t.Error("expected exact/normalized match for gpt-5.3-codex")
	}
}

// ── RPH Limits ──

func TestInferenceStats_RPHLimit(t *testing.T) {
	// Setup custom limits for test
	rphLimitsMu.Lock()
	rphLimits = map[string]int64{
		"claude-opus-4-6": 2,
		"gpt-":            5,
		"*":               10, // Default fallback
	}
	rphLoaded = true
	rphLimitsMu.Unlock()

	s := NewInferenceStats()

	// Test Exact Match
	if lim := s.GetRPHLimit("claude-opus-4-6"); lim != 2 {
		t.Errorf("GetRPHLimit(claude-opus-4-6) = %d, want 2", lim)
	}

	// Test Fuzzy Match
	if lim := s.GetRPHLimit("gpt-5-mini"); lim != 5 {
		t.Errorf("GetRPHLimit(gpt-5-mini) = %d, want 5", lim)
	}

	// Test Fallback Match
	if lim := s.GetRPHLimit("unknown-model"); lim != 10 {
		t.Errorf("GetRPHLimit(unknown-model) = %d, want 10", lim)
	}

	now := time.Now()

	// Record requests to hit the limit
	s.Record(InferenceRequest{Time: now, Model: "claude-opus-4-6"})
	s.Record(InferenceRequest{Time: now, Model: "claude-opus-4-6"})

	// Should be exceeded
	exceeded, cur, lim := s.IsRPHExceeded("claude-opus-4-6")
	if !exceeded {
		t.Errorf("IsRPHExceeded = %v, want true", exceeded)
	}
	if cur != 2 {
		t.Errorf("cur = %d, want 2", cur)
	}
	if lim != 2 {
		t.Errorf("lim = %d, want 2", lim)
	}

	// Should not be exceeded yet
	s.Record(InferenceRequest{Time: now, Model: "gpt-5-mini"})
	exceeded, _, _ = s.IsRPHExceeded("gpt-5-mini")
	if exceeded {
		t.Errorf("IsRPHExceeded for gpt-5-mini should be false")
	}
}
