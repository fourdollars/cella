package proxy

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// InferenceStats tracks model usage statistics
type InferenceStats struct {
	mu       sync.RWMutex
	models   map[string]*ModelStats
	requests []InferenceRequest // ring buffer
	maxReqs  int
	// Budget alert threshold (0 = disabled)
	DailyTokenBudget int64
	DailyCostBudget  float64 // USD
}

// ModelStats holds per-model usage data
type ModelStats struct {
	Model          string
	TotalRequests  int64
	TotalTokensIn  int64
	TotalTokensOut int64
	FirstSeen      time.Time
	LastSeen       time.Time
	Errors         int64
	// History for sparklines (60 one-minute buckets = 1 hour)
	tpmHistory    []int64   // tokens per minute, last 60 mins
	rpmHistory    []int64   // requests per minute, last 60 mins
	historyTime   time.Time // when the current minute bucket started
	curBucketTok  int64     // tokens in current minute bucket
	curBucketReqs int64     // requests in current minute bucket
	// Rolling windows
	minuteRequests []timeToken // for RPM/TPM
	dayRequests    []timeToken // for RPD
}

type timeToken struct {
	t         time.Time
	tokensIn  int64
	tokensOut int64
}

// InferenceRequest records a single API call
type InferenceRequest struct {
	Time       time.Time
	Container  string
	Domain     string
	Model      string
	Path       string
	Method     string
	TokensIn   int64
	TokensOut  int64
	Latency    time.Duration
	StatusCode int
	Error      string
}

// ModelPricing holds cost per 1M tokens for a model
type ModelPricing struct {
	InputPer1M  float64 // USD per 1M input tokens
	OutputPer1M float64 // USD per 1M output tokens
}

// knownPricing contains known model prices (USD per 1M tokens, as of 2026)
var knownPricing = map[string]ModelPricing{
	// OpenAI / GitHub Copilot
	"gpt-5-mini":    {InputPer1M: 0.15, OutputPer1M: 0.60},
	"gpt-5-1":       {InputPer1M: 2.00, OutputPer1M: 8.00},
	"gpt-5-2":       {InputPer1M: 2.50, OutputPer1M: 10.00},
	"gpt-5-2-codex": {InputPer1M: 1.50, OutputPer1M: 6.00},
	"gpt-5-3-codex": {InputPer1M: 1.50, OutputPer1M: 6.00},
	"gpt-4o":        {InputPer1M: 2.50, OutputPer1M: 10.00},
	"gpt-4o-mini":   {InputPer1M: 0.15, OutputPer1M: 0.60},
	"gpt-4-1":       {InputPer1M: 2.00, OutputPer1M: 8.00},
	"gpt-4-1-mini":  {InputPer1M: 0.40, OutputPer1M: 1.60},
	// Claude
	"claude-opus-4-6":   {InputPer1M: 15.00, OutputPer1M: 75.00},
	"claude-opus-4-5":   {InputPer1M: 15.00, OutputPer1M: 75.00},
	"claude-sonnet-4-6": {InputPer1M: 3.00, OutputPer1M: 15.00},
	"claude-sonnet-4-5": {InputPer1M: 3.00, OutputPer1M: 15.00},
	"claude-sonnet-4":   {InputPer1M: 3.00, OutputPer1M: 15.00},
	"claude-sonnet-3-5": {InputPer1M: 3.00, OutputPer1M: 15.00},
	"claude-haiku-4-5":  {InputPer1M: 0.80, OutputPer1M: 4.00},
	"claude-haiku-3-5":  {InputPer1M: 0.80, OutputPer1M: 4.00},
	// Gemini
	"gemini-3-1-pro-preview": {InputPer1M: 1.25, OutputPer1M: 5.00},
	"gemini-3-flash-preview": {InputPer1M: 0.075, OutputPer1M: 0.30},
	"gemini-2-5-pro":         {InputPer1M: 1.25, OutputPer1M: 10.00},
	"gemini-2-5-flash":       {InputPer1M: 0.075, OutputPer1M: 0.30},
}

var (
	pricingMu     sync.RWMutex
	pricingLoaded bool
)

func loadPricing() {
	pricingMu.Lock()
	defer pricingMu.Unlock()
	if pricingLoaded {
		return
	}
	defer func() { pricingLoaded = true }()

	home, err := os.UserHomeDir()
	if err != nil {
		return
	}

	configDir := filepath.Join(home, ".cella")
	configPath := filepath.Join(configDir, "pricing.yaml")

	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		// Generate default config
		os.MkdirAll(configDir, 0755)
		data, _ := yaml.Marshal(knownPricing)
		os.WriteFile(configPath, data, 0644)
	} else if data, err := os.ReadFile(configPath); err == nil {
		// Load existing user config and merge over defaults
		var customPricing map[string]ModelPricing
		if err := yaml.Unmarshal(data, &customPricing); err == nil {
			for k, p := range customPricing {
				knownPricing[k] = p
			}
		}
	}
}

// GetPricing returns pricing for a model (fuzzy match)
func GetPricing(model string) (ModelPricing, bool) {
	if !pricingLoaded {
		loadPricing()
	}

	pricingMu.RLock()
	defer pricingMu.RUnlock()

	// Exact match
	if p, ok := knownPricing[model]; ok {
		return p, true
	}
	// Fuzzy: check if model name contains a known key
	modelLower := strings.ToLower(model)
	modelNormalized := strings.ReplaceAll(modelLower, ".", "-")
	for k, p := range knownPricing {
		kNormalized := strings.ReplaceAll(strings.ToLower(k), ".", "-")
		if strings.Contains(modelNormalized, kNormalized) {
			return p, true
		}
	}
	return ModelPricing{}, false
}

// CalcCost returns the estimated USD cost for given token counts
func CalcCost(model string, tokIn, tokOut int64) float64 {
	p, ok := GetPricing(model)
	if !ok {
		return 0
	}
	return float64(tokIn)/1_000_000*p.InputPer1M + float64(tokOut)/1_000_000*p.OutputPer1M
}

// FormatCost formats cost as USD string
func FormatCost(usd float64) string {
	if usd < 0.001 {
		return fmt.Sprintf("$%.4f", usd)
	}
	if usd < 0.10 {
		return fmt.Sprintf("$%.3f", usd)
	}
	return fmt.Sprintf("$%.2f", usd)
}

// NewInferenceStats creates a stats tracker
func NewInferenceStats() *InferenceStats {
	return &InferenceStats{
		models:  make(map[string]*ModelStats),
		maxReqs: 1000,
	}
}

// Record adds an inference request
func (s *InferenceStats) Record(req InferenceRequest) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Ring buffer
	s.requests = append(s.requests, req)
	if len(s.requests) > s.maxReqs {
		s.requests = s.requests[len(s.requests)-s.maxReqs:]
	}

	// Per-model stats
	ms, ok := s.models[req.Model]
	if !ok {
		ms = &ModelStats{
			Model:       req.Model,
			FirstSeen:   req.Time,
			tpmHistory:  make([]int64, 0, 60),
			rpmHistory:  make([]int64, 0, 60),
			historyTime: req.Time.Truncate(time.Minute),
		}
		s.models[req.Model] = ms
	}

	ms.TotalRequests++
	ms.TotalTokensIn += req.TokensIn
	ms.TotalTokensOut += req.TokensOut
	ms.LastSeen = req.Time
	if req.Error != "" {
		ms.Errors++
	}

	tt := timeToken{t: req.Time, tokensIn: req.TokensIn, tokensOut: req.TokensOut}
	ms.minuteRequests = append(ms.minuteRequests, tt)
	ms.dayRequests = append(ms.dayRequests, tt)

	// Update sparkline buckets
	bucket := req.Time.Truncate(time.Minute)
	if bucket.After(ms.historyTime) {
		// New minute — flush current bucket to history
		ms.tpmHistory = appendBucket(ms.tpmHistory, ms.curBucketTok, 60)
		ms.rpmHistory = appendBucket(ms.rpmHistory, ms.curBucketReqs, 60)
		// Fill gaps
		gap := int(bucket.Sub(ms.historyTime).Minutes()) - 1
		for i := 0; i < gap && i < 60; i++ {
			ms.tpmHistory = appendBucket(ms.tpmHistory, 0, 60)
			ms.rpmHistory = appendBucket(ms.rpmHistory, 0, 60)
		}
		ms.curBucketTok = 0
		ms.curBucketReqs = 0
		ms.historyTime = bucket
	}
	ms.curBucketTok += req.TokensIn + req.TokensOut
	ms.curBucketReqs++
}

func appendBucket(hist []int64, val int64, maxLen int) []int64 {
	hist = append(hist, val)
	if len(hist) > maxLen {
		hist = hist[len(hist)-maxLen:]
	}
	return hist
}

// GetModelStats returns stats for all models, sorted by total requests desc
func (s *InferenceStats) GetModelStats() []ModelStatsSummary {
	s.mu.RLock()
	defer s.mu.RUnlock()

	now := time.Now()
	oneMinAgo := now.Add(-1 * time.Minute)
	oneHourAgo := now.Add(-1 * time.Hour)
	oneDayAgo := now.Add(-24 * time.Hour)

	var result []ModelStatsSummary
	for _, ms := range s.models {
		summary := ModelStatsSummary{
			Model:          ms.Model,
			TotalRequests:  ms.TotalRequests,
			TotalTokensIn:  ms.TotalTokensIn,
			TotalTokensOut: ms.TotalTokensOut,
			TotalTokens:    ms.TotalTokensIn + ms.TotalTokensOut,
			Errors:         ms.Errors,
			FirstSeen:      ms.FirstSeen,
			LastSeen:       ms.LastSeen,
			Cost:           CalcCost(ms.Model, ms.TotalTokensIn, ms.TotalTokensOut),
			// TPM/RPM sparklines — copy current history + current bucket
			TPMHistory: append(append([]int64{}, ms.tpmHistory...), ms.curBucketTok),
			RPMHistory: append(append([]int64{}, ms.rpmHistory...), ms.curBucketReqs),
		}

		// Prune stale window entries
		var fresh1m, freshDay []timeToken
		for _, tt := range ms.minuteRequests {
			if tt.t.After(oneMinAgo) {
				fresh1m = append(fresh1m, tt)
			}
		}
		for _, tt := range ms.dayRequests {
			if tt.t.After(oneDayAgo) {
				freshDay = append(freshDay, tt)
			}
		}

		summary.RPM = int64(len(fresh1m))
		summary.RPD = int64(len(freshDay))

		// RPH
		for _, tt := range ms.dayRequests {
			if tt.t.After(oneHourAgo) {
				summary.RPH++
			}
		}
		summary.RPHLimit = s.GetRPHLimit(ms.Model)

		// TPM
		for _, tt := range fresh1m {
			summary.TPM += tt.tokensIn + tt.tokensOut
		}

		// Today's tokens (for budget)
		for _, tt := range freshDay {
			summary.TodayTokens += tt.tokensIn + tt.tokensOut
		}
		summary.TodayCost = CalcCost(ms.Model, summary.TodayTokens/2, summary.TodayTokens/2) // approximate split

		_, summary.HasPricing = GetPricing(ms.Model)

		result = append(result, summary)
	}

	// Sort by total requests descending
	sort.Slice(result, func(i, j int) bool {
		return result[i].TotalRequests > result[j].TotalRequests
	})

	return result
}

// GetRecentRequests returns the last n requests (newest first)
func (s *InferenceStats) GetRecentRequests(n int) []InferenceRequest {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if n > len(s.requests) {
		n = len(s.requests)
	}
	result := make([]InferenceRequest, n)
	// Reverse (newest first)
	for i, r := range s.requests[len(s.requests)-n:] {
		result[n-1-i] = r
	}
	return result
}

// TotalCostToday returns the total estimated cost across all models today
func (s *InferenceStats) TotalCostToday() float64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	oneDayAgo := time.Now().Add(-24 * time.Hour)
	var total float64
	for _, req := range s.requests {
		if req.Time.After(oneDayAgo) {
			total += CalcCost(req.Model, req.TokensIn, req.TokensOut)
		}
	}
	return total
}

// ModelStatsSummary is the display-friendly version
type ModelStatsSummary struct {
	Model          string
	TotalRequests  int64
	TotalTokensIn  int64
	TotalTokensOut int64
	TotalTokens    int64
	TodayTokens    int64
	Errors         int64
	RPM            int64
	RPH            int64
	RPHLimit       int64
	RPD            int64
	TPM            int64
	Cost           float64 // total estimated cost
	TodayCost      float64 // today's estimated cost
	HasPricing     bool
	TPMHistory     []int64 // last 60 one-minute TPM buckets
	RPMHistory     []int64 // last 60 one-minute RPM buckets
	FirstSeen      time.Time
	LastSeen       time.Time
}

// ParseInferenceResponse extracts model and token usage from API response body
// Supports OpenAI /chat/completions, /responses, Anthropic /messages
func ParseInferenceResponse(body []byte) (model string, tokensIn, tokensOut int64) {
	// Try OpenAI format first (chat/completions)
	var openai struct {
		Model string `json:"model"`
		Usage struct {
			PromptTokens     int64 `json:"prompt_tokens"`
			CompletionTokens int64 `json:"completion_tokens"`
			InputTokens      int64 `json:"input_tokens"`  // some APIs use this
			OutputTokens     int64 `json:"output_tokens"` // some APIs use this
		} `json:"usage"`
	}
	if err := json.Unmarshal(body, &openai); err == nil && openai.Model != "" {
		model = openai.Model
		tokensIn = openai.Usage.PromptTokens + openai.Usage.InputTokens
		tokensOut = openai.Usage.CompletionTokens + openai.Usage.OutputTokens
		if tokensIn > 0 || tokensOut > 0 {
			return
		}
	}

	// Try Anthropic format (/v1/messages)
	var anthropic struct {
		Model string `json:"model"`
		Usage struct {
			InputTokens  int64 `json:"input_tokens"`
			OutputTokens int64 `json:"output_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(body, &anthropic); err == nil && anthropic.Model != "" {
		model = anthropic.Model
		tokensIn = anthropic.Usage.InputTokens
		tokensOut = anthropic.Usage.OutputTokens
		if tokensIn > 0 || tokensOut > 0 {
			return
		}
	}

	// Try GitHub Copilot /responses format
	var copilot struct {
		Model string `json:"model"`
		Usage struct {
			InputTokens  int64 `json:"input_tokens"`
			OutputTokens int64 `json:"output_tokens"`
			TotalTokens  int64 `json:"total_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(body, &copilot); err == nil && copilot.Model != "" {
		model = copilot.Model
		tokensIn = copilot.Usage.InputTokens
		tokensOut = copilot.Usage.OutputTokens
		if tokensIn == 0 && tokensOut == 0 && copilot.Usage.TotalTokens > 0 {
			// Split total evenly if no breakdown
			tokensIn = copilot.Usage.TotalTokens / 2
			tokensOut = copilot.Usage.TotalTokens - tokensIn
		}
	}
	return
}

// ParseInferenceRequest extracts model name from a request body.
// This ensures model tracking works even when the response body omits the model field.
func ParseInferenceRequest(body []byte) (model string) {
	var req struct {
		Model string `json:"model"`
	}
	if err := json.Unmarshal(body, &req); err == nil {
		return req.Model
	}
	return ""
}

// ParseSSETokens extracts token usage from a Server-Sent Events (streaming) response.
// Scans the event stream for the final [DONE] marker and the last usage chunk.
// Supports OpenAI chat/completions, OpenAI Responses API (/responses), and Anthropic formats.
//
// Formats handled:
//   OpenAI /chat/completions:
//     data: {"model":"gpt-4o","usage":{"prompt_tokens":100,"completion_tokens":50}}
//   OpenAI /responses (GitHub Copilot):
//     event: response.completed
//     data: {"type":"response.completed","response":{"model":"gpt-5-mini","usage":{"input_tokens":25,"output_tokens":100}}}
//   Anthropic /v1/messages:
//     data: {"type":"message_start","message":{"model":"claude-...","usage":{"input_tokens":120}}}
//     data: {"type":"message_delta","usage":{"output_tokens":45}}
func ParseSSETokens(body []byte) (model string, tokensIn, tokensOut int64) {
	lines := splitLines(body)
	for _, line := range lines {
		// SSE data lines start with "data: "
		if !hasPrefix(line, "data: ") {
			continue
		}
		data := line[6:]
		if data == "[DONE]" {
			continue
		}
		// Try to parse as a streaming chunk with usage
		type usageFields struct {
			PromptTokens     int64 `json:"prompt_tokens"`
			CompletionTokens int64 `json:"completion_tokens"`
			InputTokens      int64 `json:"input_tokens"`
			OutputTokens     int64 `json:"output_tokens"`
			TotalTokens      int64 `json:"total_tokens"`
		}
		var chunk struct {
			Model string       `json:"model"`
			Usage *usageFields `json:"usage"`
			// Anthropic message_start: nested message object
			Message *struct {
				Model string       `json:"model"`
				Usage *usageFields `json:"usage"`
			} `json:"message"`
			// OpenAI Responses API: response.completed event wraps everything in "response"
			// e.g. {"type":"response.completed","response":{"model":"gpt-5-mini","usage":{...}}}
			Response *struct {
				Model string       `json:"model"`
				Usage *usageFields `json:"usage"`
			} `json:"response"`
		}
		if err := json.Unmarshal([]byte(data), &chunk); err != nil {
			continue
		}
		// Extract model: top-level > Responses API response{} > Anthropic message{}
		if chunk.Model != "" {
			model = chunk.Model
		} else if chunk.Response != nil && chunk.Response.Model != "" {
			model = chunk.Response.Model
		} else if chunk.Message != nil && chunk.Message.Model != "" {
			model = chunk.Message.Model
		}
		// Extract usage: top-level > Responses API response{} > Anthropic message{}
		usage := chunk.Usage
		if usage == nil && chunk.Response != nil {
			usage = chunk.Response.Usage
		}
		if usage == nil && chunk.Message != nil {
			usage = chunk.Message.Usage
		}
		if usage != nil {
			if usage.PromptTokens > 0 {
				tokensIn = usage.PromptTokens
			}
			if usage.InputTokens > 0 {
				tokensIn = usage.InputTokens
			}
			if usage.CompletionTokens > 0 {
				tokensOut = usage.CompletionTokens
			}
			if usage.OutputTokens > 0 {
				tokensOut = usage.OutputTokens
			}
			if usage.TotalTokens > 0 && tokensIn == 0 && tokensOut == 0 {
				tokensIn = usage.TotalTokens / 2
				tokensOut = usage.TotalTokens - tokensIn
			}
		}
	}
	return
}
// IsStreamingResponse returns true if the Content-Type indicates SSE streaming.
func IsStreamingResponse(contentType string) bool {
	return hasPrefix(strings.ToLower(contentType), "text/event-stream")
}

// splitLines splits a byte slice on \n or \r\n
func splitLines(b []byte) []string {
	var lines []string
	start := 0
	for i := 0; i < len(b); i++ {
		if b[i] == '\n' {
			line := string(b[start:i])
			if len(line) > 0 && line[len(line)-1] == '\r' {
				line = line[:len(line)-1]
			}
			lines = append(lines, line)
			start = i + 1
		}
	}
	if start < len(b) {
		lines = append(lines, string(b[start:]))
	}
	return lines
}

// hasPrefix is a helper to avoid importing strings in test files
func hasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

// FormatTokens formats token count compactly
func FormatTokens(n int64) string {
	if n >= 1_000_000 {
		return fmt.Sprintf("%.1fM", float64(n)/1_000_000)
	}
	if n >= 1_000 {
		return fmt.Sprintf("%.1fK", float64(n)/1_000)
	}
	return fmt.Sprintf("%d", n)
}


var (
	rphLimitsMu sync.RWMutex
	rphLimits   map[string]int64
	rphLoaded   bool
)

func loadRPHLimits() {
	rphLimitsMu.Lock()
	defer rphLimitsMu.Unlock()
	if rphLoaded {
		return
	}
	rphLimits = make(map[string]int64)
	defer func() { rphLoaded = true }()

	home, err := os.UserHomeDir()
	if err != nil {
		return
	}

	configDir := filepath.Join(home, ".cella")
	configPath := filepath.Join(configDir, "rph_limits.yaml")

	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		// Generate default config
		os.MkdirAll(configDir, 0755)
		defaultLimits := map[string]int64{
			"*": 0, // 0 = disabled
		}
		data, _ := yaml.Marshal(defaultLimits)
		os.WriteFile(configPath, data, 0644)
	} else if data, err := os.ReadFile(configPath); err == nil {
		var customLimits map[string]int64
		if err := yaml.Unmarshal(data, &customLimits); err == nil {
			for k, v := range customLimits {
				rphLimits[k] = v
			}
		}
	}
}

// GetRPHLimit returns the max RPH for a model. 0 means no limit.
func (s *InferenceStats) GetRPHLimit(model string) int64 {
	if !rphLoaded {
		loadRPHLimits()
	}

	rphLimitsMu.RLock()
	defer rphLimitsMu.RUnlock()

	// Exact match
	if lim, ok := rphLimits[model]; ok {
		return lim
	}

	// Fuzzy match
	modelLower := strings.ToLower(model)
	modelNormalized := strings.ReplaceAll(modelLower, ".", "-")
	for k, lim := range rphLimits {
		if k == "*" {
			continue
		}
		kNormalized := strings.ReplaceAll(strings.ToLower(k), ".", "-")
		if strings.Contains(modelNormalized, kNormalized) {
			return lim
		}
	}

	// Fallback to wildcard
	if lim, ok := rphLimits["*"]; ok {
		return lim
	}

	return 0
}

// IsRPHExceeded checks if the current requests per hour for a model exceeds its limit.
// Returns (exceeded, current, limit).
func (s *InferenceStats) IsRPHExceeded(model string) (bool, int64, int64) {
	lim := s.GetRPHLimit(model)
	if lim <= 0 {
		return false, 0, 0
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	ms, ok := s.models[model]
	if !ok {
		return false, 0, lim
	}

	oneHourAgo := time.Now().Add(-1 * time.Hour)
	var rph int64
	for _, tt := range ms.dayRequests {
		if tt.t.After(oneHourAgo) {
			rph++
		}
	}

	return rph >= lim, rph, lim
}
