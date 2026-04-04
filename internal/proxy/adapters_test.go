package proxy

import (
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
)

// ── Anthropic Adapter ────────────────────────────────────────────────────────

func TestAnthropicAdapter_TransformRequest_Basic(t *testing.T) {
	body := []byte(`{
		"model": "claude-sonnet-4-5",
		"max_tokens": 1024,
		"system": "You are helpful.",
		"messages": [
			{"role": "user", "content": "Hello!"}
		]
	}`)

	r := &http.Request{
		Header: http.Header{"X-Api-Key": []string{"sk-ant-xxx"}, "Anthropic-Version": []string{"2023-06-01"}},
		URL:    &url.URL{Path: "/v1/messages"},
	}

	a := &AnthropicAdapter{}
	newBody, newPath, err := a.TransformRequest(r, body, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if newPath != "/v1/chat/completions" {
		t.Errorf("expected path /v1/chat/completions, got %s", newPath)
	}

	var oai oaiRequest
	if err := json.Unmarshal(newBody, &oai); err != nil {
		t.Fatalf("invalid output JSON: %v", err)
	}
	if oai.Model != "claude-sonnet-4-5" {
		t.Errorf("expected model claude-sonnet-4-5, got %s", oai.Model)
	}
	if len(oai.Messages) != 2 {
		t.Errorf("expected 2 messages (system+user), got %d", len(oai.Messages))
	}
	if oai.Messages[0].Role != "system" || oai.Messages[0].Content != "You are helpful." {
		t.Errorf("bad system message: %+v", oai.Messages[0])
	}
	if oai.Messages[1].Role != "user" || oai.Messages[1].Content != "Hello!" {
		t.Errorf("bad user message: %+v", oai.Messages[1])
	}
	if r.Header.Get("X-Api-Key") != "" {
		t.Error("x-api-key header should be stripped")
	}
}

func TestAnthropicAdapter_TransformRequest_ModelOverride(t *testing.T) {
	body := []byte(`{"model":"claude-opus-4-6","max_tokens":100,"messages":[{"role":"user","content":"hi"}]}`)
	r := &http.Request{Header: http.Header{}, URL: &url.URL{Path: "/v1/messages"}}

	a := &AnthropicAdapter{}
	newBody, _, err := a.TransformRequest(r, body, "llama3.3:70b")
	if err != nil {
		t.Fatal(err)
	}
	var oai oaiRequest
	json.Unmarshal(newBody, &oai)
	if oai.Model != "llama3.3:70b" {
		t.Errorf("expected model override llama3.3:70b, got %s", oai.Model)
	}
}

func TestAnthropicAdapter_TransformRequest_ContentBlocks(t *testing.T) {
	body := []byte(`{
		"model": "claude-sonnet-4-5",
		"max_tokens": 100,
		"messages": [{"role": "user", "content": [{"type": "text", "text": "Part A"}, {"type": "text", "text": " Part B"}]}]
	}`)
	r := &http.Request{Header: http.Header{}, URL: &url.URL{Path: "/v1/messages"}}

	a := &AnthropicAdapter{}
	newBody, _, _ := a.TransformRequest(r, body, "")
	var oai oaiRequest
	json.Unmarshal(newBody, &oai)
	if oai.Messages[0].Content != "Part A Part B" {
		t.Errorf("content block join failed: %q", oai.Messages[0].Content)
	}
}

func TestAnthropicAdapter_TransformResponse_JSON(t *testing.T) {
	upstreamJSON := []byte(`{
		"id":"chatcmpl-1","object":"chat.completion","model":"llama3.3",
		"choices":[{"index":0,"message":{"role":"assistant","content":"Hi there!"},"finish_reason":"stop"}],
		"usage":{"prompt_tokens":10,"completion_tokens":5}
	}`)

	a := &AnthropicAdapter{}
	out, err := a.TransformResponse(upstreamJSON, "claude-sonnet-4-5", false)
	if err != nil {
		t.Fatal(err)
	}

	var resp anthropicResponse
	if err := json.Unmarshal(out, &resp); err != nil {
		t.Fatalf("output not valid Anthropic JSON: %v\nbody: %s", err, out)
	}
	if resp.Type != "message" {
		t.Errorf("expected type message, got %s", resp.Type)
	}
	if resp.StopReason != "end_turn" {
		t.Errorf("expected stop_reason end_turn, got %s", resp.StopReason)
	}
	if len(resp.Content) == 0 || resp.Content[0].Text != "Hi there!" {
		t.Errorf("unexpected content: %+v", resp.Content)
	}
	if resp.Usage.InputTokens != 10 || resp.Usage.OutputTokens != 5 {
		t.Errorf("usage mismatch: %+v", resp.Usage)
	}
}

func TestAnthropicAdapter_TransformResponse_Stream(t *testing.T) {
	// Simulated OpenAI SSE stream from Ollama
	sse := []byte("data: {\"id\":\"1\",\"model\":\"llama3.3\",\"choices\":[{\"delta\":{\"content\":\"Hello\"},\"finish_reason\":null}]}\n\n" +
		"data: {\"id\":\"1\",\"model\":\"llama3.3\",\"choices\":[{\"delta\":{\"content\":\" world\"},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":8,\"completion_tokens\":2}}\n\n" +
		"data: [DONE]\n\n")

	a := &AnthropicAdapter{}
	out, err := a.TransformResponse(sse, "claude-sonnet-4-5", true)
	if err != nil {
		t.Fatal(err)
	}
	outStr := string(out)
	if !contains(outStr, "message_start") {
		t.Error("expected message_start event")
	}
	if !contains(outStr, "content_block_delta") {
		t.Error("expected content_block_delta event")
	}
	if !contains(outStr, "message_stop") {
		t.Error("expected message_stop event")
	}
	if !contains(outStr, "Hello") || !contains(outStr, " world") {
		t.Error("expected text deltas in output")
	}
}

// ── Gemini Adapter ────────────────────────────────────────────────────────────

func TestGeminiAdapter_TransformRequest_Basic(t *testing.T) {
	body := []byte(`{
		"contents": [{"role": "user", "parts": [{"text": "What is 2+2?"}]}],
		"generationConfig": {"maxOutputTokens": 256, "temperature": 0.7}
	}`)

	r := &http.Request{
		Header: http.Header{"X-Goog-Api-Key": []string{"AIza-xxx"}},
		URL:    &url.URL{Path: "/v1beta/models/gemini-2.5-pro:generateContent"},
	}

	g := &GeminiAdapter{}
	newBody, newPath, err := g.TransformRequest(r, body, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if newPath != "/v1/chat/completions" {
		t.Errorf("expected /v1/chat/completions, got %s", newPath)
	}

	var oai oaiRequest
	if err := json.Unmarshal(newBody, &oai); err != nil {
		t.Fatalf("invalid output JSON: %v", err)
	}
	if oai.Model != "gemini-2.5-pro" {
		t.Errorf("model not extracted from path, got %s", oai.Model)
	}
	if len(oai.Messages) != 1 || oai.Messages[0].Role != "user" {
		t.Errorf("unexpected messages: %+v", oai.Messages)
	}
	if oai.Messages[0].Content != "What is 2+2?" {
		t.Errorf("unexpected content: %q", oai.Messages[0].Content)
	}
	if oai.MaxTokens != 256 {
		t.Errorf("maxOutputTokens not mapped, got %d", oai.MaxTokens)
	}
	if r.Header.Get("X-Goog-Api-Key") != "" {
		t.Error("x-goog-api-key should be stripped")
	}
}

func TestGeminiAdapter_TransformRequest_ModelRole(t *testing.T) {
	body := []byte(`{
		"contents": [
			{"role": "user", "parts": [{"text": "Hi"}]},
			{"role": "model", "parts": [{"text": "Hello!"}]},
			{"role": "user", "parts": [{"text": "How are you?"}]}
		]
	}`)
	r := &http.Request{
		Header: http.Header{},
		URL:    &url.URL{Path: "/v1beta/models/gemini-2.5-flash:generateContent"},
	}

	g := &GeminiAdapter{}
	newBody, _, _ := g.TransformRequest(r, body, "")

	var oai oaiRequest
	json.Unmarshal(newBody, &oai)
	if len(oai.Messages) != 3 {
		t.Fatalf("expected 3 messages, got %d", len(oai.Messages))
	}
	if oai.Messages[1].Role != "assistant" {
		t.Errorf("Gemini 'model' role should map to 'assistant', got %q", oai.Messages[1].Role)
	}
}

func TestGeminiAdapter_TransformRequest_SystemInstruction(t *testing.T) {
	body := []byte(`{
		"systemInstruction": {"parts": [{"text": "You are a calculator."}]},
		"contents": [{"role": "user", "parts": [{"text": "1+1"}]}]
	}`)
	r := &http.Request{Header: http.Header{}, URL: &url.URL{Path: "/v1beta/models/gemini-2.5-pro:generateContent"}}

	g := &GeminiAdapter{}
	newBody, _, _ := g.TransformRequest(r, body, "")
	var oai oaiRequest
	json.Unmarshal(newBody, &oai)
	if len(oai.Messages) != 2 || oai.Messages[0].Role != "system" {
		t.Errorf("systemInstruction not mapped: %+v", oai.Messages)
	}
}

func TestGeminiAdapter_TransformResponse_JSON(t *testing.T) {
	upstreamJSON := []byte(`{
		"id":"1","object":"chat.completion","model":"gemini-2.5-pro",
		"choices":[{"index":0,"message":{"role":"assistant","content":"Four."},"finish_reason":"stop"}],
		"usage":{"prompt_tokens":5,"completion_tokens":2}
	}`)

	g := &GeminiAdapter{}
	out, err := g.TransformResponse(upstreamJSON, "gemini-2.5-pro", false)
	if err != nil {
		t.Fatal(err)
	}

	var resp geminiResponse
	if err := json.Unmarshal(out, &resp); err != nil {
		t.Fatalf("not valid Gemini JSON: %v\nbody: %s", err, out)
	}
	if len(resp.Candidates) != 1 {
		t.Fatalf("expected 1 candidate")
	}
	if resp.Candidates[0].Content.Parts[0].Text != "Four." {
		t.Errorf("unexpected text: %q", resp.Candidates[0].Content.Parts[0].Text)
	}
	if resp.Candidates[0].Content.Role != "model" {
		t.Errorf("role should be 'model', got %q", resp.Candidates[0].Content.Role)
	}
	if resp.UsageMetadata.PromptTokenCount != 5 {
		t.Errorf("prompt token count mismatch: %d", resp.UsageMetadata.PromptTokenCount)
	}
}

func TestGeminiAdapter_TransformResponse_Stream(t *testing.T) {
	sse := []byte("data: {\"id\":\"1\",\"model\":\"gemini-2.5-pro\",\"choices\":[{\"delta\":{\"content\":\"Four\"},\"finish_reason\":null}]}\n\n" +
		"data: {\"id\":\"1\",\"model\":\"gemini-2.5-pro\",\"choices\":[{\"delta\":{\"content\":\".\"},\"finish_reason\":\"stop\"}]}\n\n" +
		"data: [DONE]\n\n")

	g := &GeminiAdapter{}
	out, err := g.TransformResponse(sse, "gemini-2.5-pro", true)
	if err != nil {
		t.Fatal(err)
	}
	outStr := string(out)
	if !contains(outStr, `"model"`) {
		t.Error("expected model in response")
	}
	if !contains(outStr, "Four") {
		t.Error("expected text in response")
	}
}

// ── GetAdapter ────────────────────────────────────────────────────────────────

func TestGetAdapter(t *testing.T) {
	if GetAdapter(AdapterAnthropic) == nil {
		t.Error("expected AnthropicAdapter for AdapterAnthropic")
	}
	if GetAdapter(AdapterGemini) == nil {
		t.Error("expected GeminiAdapter for AdapterGemini")
	}
	if GetAdapter(AdapterNone) != nil {
		t.Error("expected nil for AdapterNone")
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		func() bool {
			for i := 0; i <= len(s)-len(substr); i++ {
				if s[i:i+len(substr)] == substr {
					return true
				}
			}
			return false
		}())
}
