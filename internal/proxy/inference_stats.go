package proxy

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// InferenceStats tracks model usage statistics
type InferenceStats struct {
	mu       sync.RWMutex
	models   map[string]*ModelStats
	requests []InferenceRequest // ring buffer
	maxReqs  int
}

// ModelStats holds per-model usage data
type ModelStats struct {
	Model         string
	TotalRequests int64
	TotalTokensIn int64  // prompt tokens
	TotalTokensOut int64 // completion tokens
	FirstSeen     time.Time
	LastSeen      time.Time
	Errors        int64
	// RPM/TPM windows
	minuteRequests []time.Time // timestamps for RPM calculation
	dayRequests    []time.Time // timestamps for RPD calculation
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
			Model:     req.Model,
			FirstSeen: req.Time,
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

	ms.minuteRequests = append(ms.minuteRequests, req.Time)
	ms.dayRequests = append(ms.dayRequests, req.Time)
}

// GetModelStats returns stats for all models
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
			Model:         ms.Model,
			TotalRequests: ms.TotalRequests,
			TotalTokensIn: ms.TotalTokensIn,
			TotalTokensOut: ms.TotalTokensOut,
			TotalTokens:   ms.TotalTokensIn + ms.TotalTokensOut,
			Errors:        ms.Errors,
			FirstSeen:     ms.FirstSeen,
			LastSeen:      ms.LastSeen,
		}

		// RPM: requests in last minute
		for _, t := range ms.minuteRequests {
			if t.After(oneMinAgo) {
				summary.RPM++
			}
		}

		// RPH: requests in last hour
		for _, t := range ms.dayRequests {
			if t.After(oneHourAgo) {
				summary.RPH++
			}
		}

		// RPD: requests in last day
		for _, t := range ms.dayRequests {
			if t.After(oneDayAgo) {
				summary.RPD++
			}
		}

		// TPM: tokens in last minute
		for _, r := range s.requests {
			if r.Model == ms.Model && r.Time.After(oneMinAgo) {
				summary.TPM += r.TokensIn + r.TokensOut
			}
		}

		result = append(result, summary)
	}
	return result
}

// GetRecentRequests returns the last n requests
func (s *InferenceStats) GetRecentRequests(n int) []InferenceRequest {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if n > len(s.requests) {
		n = len(s.requests)
	}
	result := make([]InferenceRequest, n)
	copy(result, s.requests[len(s.requests)-n:])
	return result
}

// ModelStatsSummary is the display-friendly version
type ModelStatsSummary struct {
	Model         string
	TotalRequests int64
	TotalTokensIn int64
	TotalTokensOut int64
	TotalTokens   int64
	Errors        int64
	RPM           int64 // requests per minute
	RPH           int64 // requests per hour
	RPD           int64 // requests per day
	TPM           int64 // tokens per minute
	FirstSeen     time.Time
	LastSeen      time.Time
}

// ParseInferenceResponse extracts model and token usage from API response body
func ParseInferenceResponse(body []byte) (model string, tokensIn, tokensOut int64) {
	var resp struct {
		Model string `json:"model"`
		Usage struct {
			PromptTokens     int64 `json:"prompt_tokens"`
			CompletionTokens int64 `json:"completion_tokens"`
			TotalTokens      int64 `json:"total_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(body, &resp); err == nil {
		model = resp.Model
		tokensIn = resp.Usage.PromptTokens
		tokensOut = resp.Usage.CompletionTokens
	}
	return
}

// FormatTokens formats token count
func FormatTokens(n int64) string {
	if n >= 1_000_000 {
		return fmt.Sprintf("%.1fM", float64(n)/1_000_000)
	}
	if n >= 1_000 {
		return fmt.Sprintf("%.1fK", float64(n)/1_000)
	}
	return fmt.Sprintf("%d", n)
}
