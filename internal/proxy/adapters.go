package proxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// AdapterKind identifies the format adapter to apply on a route
type AdapterKind string

const (
	AdapterNone      AdapterKind = ""
	AdapterAnthropic AdapterKind = "anthropic"
	AdapterGemini    AdapterKind = "gemini"
)

// GetAdapter returns the adapter for a given kind (nil = no transform needed)
func GetAdapter(kind AdapterKind) Adapter {
	switch kind {
	case AdapterAnthropic:
		return &AnthropicAdapter{}
	case AdapterGemini:
		return &GeminiAdapter{}
	default:
		return nil
	}
}

// Adapter transforms requests/responses between incompatible API formats.
// All adapters target the OpenAI chat/completions format as the common wire format
// used by Ollama's /v1/chat/completions endpoint.
type Adapter interface {
	// TransformRequest converts the original request body to OpenAI format.
	// Returns: transformed body, new path (empty = keep current), error.
	// Also strips provider-specific auth headers from r.Header.
	TransformRequest(r *http.Request, body []byte, modelOverride string) (newBody []byte, newPath string, err error)

	// TransformResponse converts an OpenAI-format response (from Ollama) back
	// to the original provider format expected by the client application.
	// origModel is the model name from the original request (fallback if Ollama omits it).
	// isStream indicates the response body contains OpenAI SSE data.
	TransformResponse(upstreamBody []byte, origModel string, isStream bool) ([]byte, error)
}

// ─────────────────────────────────────────────────────────────────────────────
// Shared OpenAI types (Ollama target format)
// ─────────────────────────────────────────────────────────────────────────────

type oaiRequest struct {
	Model       string    `json:"model"`
	Messages    []oaiMsg  `json:"messages"`
	MaxTokens   int       `json:"max_tokens,omitempty"`
	Temperature *float64  `json:"temperature,omitempty"`
	TopP        *float64  `json:"top_p,omitempty"`
	Stream      bool      `json:"stream"`
	Stop        []string  `json:"stop,omitempty"`
}

type oaiMsg struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type oaiResponse struct {
	ID      string `json:"id"`
	Object  string `json:"object"`
	Model   string `json:"model"`
	Choices []struct {
		Index        int    `json:"index"`
		Message      oaiMsg `json:"message"`
		FinishReason string `json:"finish_reason"`
	} `json:"choices"`
	Usage struct {
		PromptTokens     int64 `json:"prompt_tokens"`
		CompletionTokens int64 `json:"completion_tokens"`
	} `json:"usage"`
}

// ─────────────────────────────────────────────────────────────────────────────
// Anthropic Adapter: /v1/messages ↔ /v1/chat/completions
// ─────────────────────────────────────────────────────────────────────────────

// AnthropicAdapter translates between Anthropic Messages API and OpenAI Chat Completions.
type AnthropicAdapter struct{}

// -- Anthropic request types --

type anthropicRequest struct {
	Model         string           `json:"model"`
	MaxTokens     int              `json:"max_tokens"`
	System        string           `json:"system,omitempty"`
	Messages      []anthropicMsg   `json:"messages"`
	Temperature   *float64         `json:"temperature,omitempty"`
	TopP          *float64         `json:"top_p,omitempty"`
	TopK          *int             `json:"top_k,omitempty"`
	Stream        bool             `json:"stream"`
	StopSequences []string         `json:"stop_sequences,omitempty"`
}

type anthropicMsg struct {
	Role    string          `json:"role"`
	Content json.RawMessage `json:"content"` // string OR []contentBlock
}

type anthropicContentBlock struct {
	Type string `json:"type"`
	Text string `json:"text,omitempty"`
}

// extractAnthropicText flattens Anthropic content (string or []contentBlock) to plain text.
func extractAnthropicText(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	var blocks []anthropicContentBlock
	if err := json.Unmarshal(raw, &blocks); err == nil {
		var parts []string
		for _, b := range blocks {
			if b.Type == "text" && b.Text != "" {
				parts = append(parts, b.Text)
			}
		}
		return strings.Join(parts, "")
	}
	return string(raw)
}

func (a *AnthropicAdapter) TransformRequest(r *http.Request, body []byte, modelOverride string) ([]byte, string, error) {
	var req anthropicRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return body, "", fmt.Errorf("anthropic adapter: parse request: %w", err)
	}

	var msgs []oaiMsg

	// Prepend system message if present (Anthropic top-level → OpenAI system role)
	if req.System != "" {
		msgs = append(msgs, oaiMsg{Role: "system", Content: req.System})
	}

	for _, m := range req.Messages {
		msgs = append(msgs, oaiMsg{
			Role:    m.Role, // "user"/"assistant" — same in both APIs
			Content: extractAnthropicText(m.Content),
		})
	}

	model := req.Model
	if modelOverride != "" {
		model = modelOverride
	}

	out := oaiRequest{
		Model:       model,
		Messages:    msgs,
		MaxTokens:   req.MaxTokens,
		Temperature: req.Temperature,
		TopP:        req.TopP,
		Stream:      req.Stream,
		Stop:        req.StopSequences,
	}

	outBody, err := json.Marshal(out)
	if err != nil {
		return body, "", err
	}

	// Strip Anthropic-specific auth headers
	r.Header.Del("x-api-key")
	r.Header.Del("anthropic-version")
	r.Header.Del("anthropic-beta")
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Content-Length", fmt.Sprint(len(outBody)))

	return outBody, "/v1/chat/completions", nil
}

// -- Anthropic response types --

type anthropicResponse struct {
	ID           string                   `json:"id"`
	Type         string                   `json:"type"`
	Role         string                   `json:"role"`
	Model        string                   `json:"model"`
	Content      []anthropicContentBlock  `json:"content"`
	StopReason   string                   `json:"stop_reason"`
	StopSequence *string                  `json:"stop_sequence"`
	Usage        struct {
		InputTokens  int64 `json:"input_tokens"`
		OutputTokens int64 `json:"output_tokens"`
	} `json:"usage"`
}

func finishReasonToAnthropic(reason string) string {
	switch reason {
	case "stop":
		return "end_turn"
	case "length":
		return "max_tokens"
	case "tool_calls":
		return "tool_use"
	default:
		return "end_turn"
	}
}

func (a *AnthropicAdapter) TransformResponse(upstreamBody []byte, origModel string, isStream bool) ([]byte, error) {
	if isStream {
		return a.transformStream(upstreamBody, origModel)
	}
	return a.transformJSON(upstreamBody, origModel)
}

func (a *AnthropicAdapter) transformJSON(body []byte, origModel string) ([]byte, error) {
	var oai oaiResponse
	if err := json.Unmarshal(body, &oai); err != nil {
		return body, nil // pass through on parse error
	}

	text := ""
	finishReason := "end_turn"
	if len(oai.Choices) > 0 {
		text = oai.Choices[0].Message.Content
		finishReason = finishReasonToAnthropic(oai.Choices[0].FinishReason)
	}

	model := origModel
	if oai.Model != "" {
		model = oai.Model
	}

	resp := anthropicResponse{
		ID:    "msg_" + oai.ID,
		Type:  "message",
		Role:  "assistant",
		Model: model,
		Content: []anthropicContentBlock{
			{Type: "text", Text: text},
		},
		StopReason:   finishReason,
		StopSequence: nil,
	}
	resp.Usage.InputTokens = oai.Usage.PromptTokens
	resp.Usage.OutputTokens = oai.Usage.CompletionTokens

	return json.Marshal(resp)
}

// transformStream converts OpenAI SSE → Anthropic SSE.
// We buffer the full stream first (already done by caller), then emit Anthropic events.
func (a *AnthropicAdapter) transformStream(body []byte, origModel string) ([]byte, error) {
	// Pass 1: collect all text deltas + usage + model
	type delta struct{ text string }
	var deltas []delta
	var inputTokens, outputTokens int64
	model := origModel
	finishReason := "end_turn"
	msgID := fmt.Sprintf("msg_ollama_%d", time.Now().UnixNano())

	for _, line := range splitLines(body) {
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		data := line[6:]
		if data == "[DONE]" {
			continue
		}
		var chunk struct {
			Model   string `json:"model"`
			Choices []struct {
				Delta struct {
					Content string `json:"content"`
				} `json:"delta"`
				FinishReason string `json:"finish_reason"`
			} `json:"choices"`
			Usage *struct {
				PromptTokens     int64 `json:"prompt_tokens"`
				CompletionTokens int64 `json:"completion_tokens"`
			} `json:"usage"`
		}
		if err := json.Unmarshal([]byte(data), &chunk); err != nil {
			continue
		}
		if chunk.Model != "" {
			model = chunk.Model
		}
		if chunk.Usage != nil {
			inputTokens = chunk.Usage.PromptTokens
			outputTokens = chunk.Usage.CompletionTokens
		}
		if len(chunk.Choices) > 0 {
			if t := chunk.Choices[0].Delta.Content; t != "" {
				deltas = append(deltas, delta{text: t})
			}
			if r := chunk.Choices[0].FinishReason; r != "" && r != "null" {
				finishReason = finishReasonToAnthropic(r)
			}
		}
	}

	// Pass 2: emit Anthropic SSE events
	var buf bytes.Buffer

	startMsg := map[string]interface{}{
		"type": "message_start",
		"message": map[string]interface{}{
			"id": msgID, "type": "message", "role": "assistant",
			"content": []interface{}{}, "model": model,
			"stop_reason": nil, "stop_sequence": nil,
			"usage": map[string]int64{"input_tokens": inputTokens, "output_tokens": 0},
		},
	}
	sseEvent(&buf, "message_start", startMsg)
	sseEvent(&buf, "content_block_start", map[string]interface{}{
		"type": "content_block_start", "index": 0,
		"content_block": map[string]string{"type": "text", "text": ""},
	})
	sseEvent(&buf, "ping", map[string]string{"type": "ping"})

	for _, d := range deltas {
		sseEvent(&buf, "content_block_delta", map[string]interface{}{
			"type": "content_block_delta", "index": 0,
			"delta": map[string]string{"type": "text_delta", "text": d.text},
		})
	}

	sseEvent(&buf, "content_block_stop", map[string]interface{}{"type": "content_block_stop", "index": 0})
	sseEvent(&buf, "message_delta", map[string]interface{}{
		"type":  "message_delta",
		"delta": map[string]interface{}{"stop_reason": finishReason, "stop_sequence": nil},
		"usage": map[string]int64{"output_tokens": outputTokens},
	})
	sseEvent(&buf, "message_stop", map[string]string{"type": "message_stop"})

	return buf.Bytes(), nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Gemini Adapter: generateContent ↔ /v1/chat/completions
// ─────────────────────────────────────────────────────────────────────────────

// GeminiAdapter translates between Gemini generateContent API and OpenAI Chat Completions.
type GeminiAdapter struct{}

// -- Gemini request types --

type geminiRequest struct {
	Contents          []geminiContent  `json:"contents"`
	SystemInstruction *geminiContent   `json:"systemInstruction,omitempty"`
	GenerationConfig  *geminiGenConfig `json:"generationConfig,omitempty"`
}

type geminiContent struct {
	Role  string       `json:"role,omitempty"`
	Parts []geminiPart `json:"parts"`
}

type geminiPart struct {
	Text string `json:"text,omitempty"`
}

type geminiGenConfig struct {
	MaxOutputTokens *int     `json:"maxOutputTokens,omitempty"`
	Temperature     *float64 `json:"temperature,omitempty"`
	TopP            *float64 `json:"topP,omitempty"`
	StopSequences   []string `json:"stopSequences,omitempty"`
}

func joinGeminiParts(parts []geminiPart) string {
	var sb strings.Builder
	for _, p := range parts {
		sb.WriteString(p.Text)
	}
	return sb.String()
}

// extractGeminiModel extracts the model name from a Gemini URL path.
// e.g. /v1beta/models/gemini-2.5-pro:generateContent → "gemini-2.5-pro"
func extractGeminiModel(path string) string {
	for _, seg := range strings.Split(path, "/") {
		if strings.Contains(seg, ":") {
			return strings.Split(seg, ":")[0]
		}
	}
	return ""
}

func (g *GeminiAdapter) TransformRequest(r *http.Request, body []byte, modelOverride string) ([]byte, string, error) {
	var req geminiRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return body, "", fmt.Errorf("gemini adapter: parse request: %w", err)
	}

	isStream := strings.Contains(r.URL.Path, "streamGenerateContent")

	model := modelOverride
	if model == "" {
		model = extractGeminiModel(r.URL.Path)
	}
	if model == "" {
		model = "gemini-2.5-flash"
	}

	var msgs []oaiMsg

	// System instruction → system role
	if req.SystemInstruction != nil {
		if text := joinGeminiParts(req.SystemInstruction.Parts); text != "" {
			msgs = append(msgs, oaiMsg{Role: "system", Content: text})
		}
	}

	// Contents: Gemini uses "user"/"model", OpenAI uses "user"/"assistant"
	for _, c := range req.Contents {
		role := "user"
		if c.Role == "model" {
			role = "assistant"
		}
		msgs = append(msgs, oaiMsg{Role: role, Content: joinGeminiParts(c.Parts)})
	}

	out := oaiRequest{
		Model:    model,
		Messages: msgs,
		Stream:   isStream,
	}
	if req.GenerationConfig != nil {
		if req.GenerationConfig.MaxOutputTokens != nil {
			out.MaxTokens = *req.GenerationConfig.MaxOutputTokens
		}
		out.Temperature = req.GenerationConfig.Temperature
		out.TopP = req.GenerationConfig.TopP
		out.Stop = req.GenerationConfig.StopSequences
	}

	outBody, err := json.Marshal(out)
	if err != nil {
		return body, "", err
	}

	// Strip Gemini-specific auth
	r.Header.Del("x-goog-api-key")
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Content-Length", fmt.Sprint(len(outBody)))

	return outBody, "/v1/chat/completions", nil
}

// -- Gemini response types --

type geminiResponse struct {
	Candidates    []geminiCandidate `json:"candidates"`
	UsageMetadata geminiUsageMeta   `json:"usageMetadata"`
	ModelVersion  string            `json:"modelVersion,omitempty"`
}

type geminiCandidate struct {
	Content      geminiContent `json:"content"`
	FinishReason string        `json:"finishReason"`
	Index        int           `json:"index"`
}

type geminiUsageMeta struct {
	PromptTokenCount     int64 `json:"promptTokenCount"`
	CandidatesTokenCount int64 `json:"candidatesTokenCount"`
	TotalTokenCount      int64 `json:"totalTokenCount"`
}

func finishReasonToGemini(reason string) string {
	switch reason {
	case "length":
		return "MAX_TOKENS"
	default:
		return "STOP"
	}
}

func (g *GeminiAdapter) TransformResponse(upstreamBody []byte, origModel string, isStream bool) ([]byte, error) {
	if isStream {
		return g.transformStream(upstreamBody, origModel)
	}
	return g.transformJSON(upstreamBody, origModel)
}

func (g *GeminiAdapter) transformJSON(body []byte, origModel string) ([]byte, error) {
	var oai oaiResponse
	if err := json.Unmarshal(body, &oai); err != nil {
		return body, nil
	}

	text := ""
	finishReason := "STOP"
	if len(oai.Choices) > 0 {
		text = oai.Choices[0].Message.Content
		finishReason = finishReasonToGemini(oai.Choices[0].FinishReason)
	}

	model := origModel
	if oai.Model != "" {
		model = oai.Model
	}

	resp := geminiResponse{
		Candidates: []geminiCandidate{{
			Content: geminiContent{
				Role:  "model",
				Parts: []geminiPart{{Text: text}},
			},
			FinishReason: finishReason,
			Index:        0,
		}},
		UsageMetadata: geminiUsageMeta{
			PromptTokenCount:     oai.Usage.PromptTokens,
			CandidatesTokenCount: oai.Usage.CompletionTokens,
			TotalTokenCount:      oai.Usage.PromptTokens + oai.Usage.CompletionTokens,
		},
		ModelVersion: model,
	}

	return json.Marshal(resp)
}

// transformStream converts OpenAI SSE → Gemini streaming format.
// Gemini streaming: each chunk is a full geminiResponse JSON on a "data: ..." SSE line.
func (g *GeminiAdapter) transformStream(body []byte, origModel string) ([]byte, error) {
	var buf bytes.Buffer

	for _, line := range splitLines(body) {
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		data := line[6:]
		if data == "[DONE]" {
			continue
		}

		var chunk struct {
			Model   string `json:"model"`
			Choices []struct {
				Delta struct {
					Content string `json:"content"`
				} `json:"delta"`
				FinishReason string `json:"finish_reason"`
			} `json:"choices"`
			Usage *struct {
				PromptTokens     int64 `json:"prompt_tokens"`
				CompletionTokens int64 `json:"completion_tokens"`
			} `json:"usage"`
		}
		if err := json.Unmarshal([]byte(data), &chunk); err != nil {
			continue
		}

		text := ""
		finishReason := "STOP"
		if len(chunk.Choices) > 0 {
			text = chunk.Choices[0].Delta.Content
			finishReason = finishReasonToGemini(chunk.Choices[0].FinishReason)
		}

		var inputTok, outputTok int64
		if chunk.Usage != nil {
			inputTok = chunk.Usage.PromptTokens
			outputTok = chunk.Usage.CompletionTokens
		}

		resp := geminiResponse{
			Candidates: []geminiCandidate{{
				Content:      geminiContent{Role: "model", Parts: []geminiPart{{Text: text}}},
				FinishReason: finishReason,
				Index:        0,
			}},
			UsageMetadata: geminiUsageMeta{
				PromptTokenCount:     inputTok,
				CandidatesTokenCount: outputTok,
				TotalTokenCount:      inputTok + outputTok,
			},
		}

		jsonBytes, _ := json.Marshal(resp)
		fmt.Fprintf(&buf, "data: %s\n\n", string(jsonBytes))
	}

	return buf.Bytes(), nil
}

// ─────────────────────────────────────────────────────────────────────────────
// SSE helper
// ─────────────────────────────────────────────────────────────────────────────

func sseEvent(buf *bytes.Buffer, event string, data interface{}) {
	b, _ := json.Marshal(data)
	fmt.Fprintf(buf, "event: %s\ndata: %s\n\n", event, string(b))
}
