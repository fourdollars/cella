package proxy

import "testing"

func TestIsInferencePathCopilotModels(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		// Standard paths (existing)
		{"/chat/completions", true},
		{"/v1/chat/completions", true},
		{"/v1/messages", true},
		{"/v1/embeddings", true},
		{"/responses", true},
		// GitHub Copilot model-namespaced paths
		{"/models/claude-sonnet-4.6/chat/completions", true},
		{"/models/claude-opus-4.6/chat/completions", true},
		{"/models/gpt-5-mini/chat/completions", true},
		{"/models/gpt-5/chat/completions", true},
		{"/models/gemini-2.5-pro/chat/completions", true},
		{"/models/claude-opus-4.5/chat/completions", true},
		{"/models/gpt-5.3-codex/chat/completions", true},
		{"/models/gemini-3.1-pro-preview/chat/completions", true},
		// Azure-style
		{"/openai/deployments/gpt-5/chat/completions", true},
		// Should NOT match
		{"/v1/models", false},
		{"/health", false},
		{"/", false},
	}
	for _, tc := range cases {
		got := isInferencePath(tc.path)
		if got != tc.want {
			t.Errorf("isInferencePath(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}
