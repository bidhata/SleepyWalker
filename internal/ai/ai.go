package ai

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/go-resty/resty/v2"
	"sleepywalker/internal/config"
	"sleepywalker/internal/scanner"
)

type openRouterRequest struct {
	Model       string    `json:"model"`
	Messages    []Message `json:"messages"`
	MaxTokens   int       `json:"max_tokens,omitempty"`
	Temperature float64   `json:"temperature,omitempty"`
}

type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type openRouterResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
}

// AIVerdict is the structured response we request from the LLM.
type AIVerdict struct {
	Vulnerable bool    `json:"vulnerable"`
	Confidence float64 `json:"confidence"`
	Payload    string  `json:"payload"`
	Reasoning  string  `json:"reasoning"`
}

const maxRetries = 3

// AnalyzeEndpoint sends the entry point to the configured AI provider and
// returns whether it is vulnerable. Uses structured JSON output with retry.
func AnalyzeEndpoint(cfg config.Config, ep scanner.EntryPoint) (vulnerable bool, suggestion string, err error) {
	prompt := buildPrompt(ep)

	for attempt := 1; attempt <= maxRetries; attempt++ {
		verdict, reqErr := callProvider(cfg, prompt)
		if reqErr != nil {
			if attempt == maxRetries {
				return false, "", fmt.Errorf("AI analysis failed after %d retries: %w", maxRetries, reqErr)
			}
			backoff := time.Duration(attempt*attempt) * time.Second
			log.Printf("[AI] Attempt %d failed (%v), retrying in %v…", attempt, reqErr, backoff)
			time.Sleep(backoff)
			continue
		}
		return verdict.Vulnerable, verdict.Payload, nil
	}
	return false, "", fmt.Errorf("AI analysis exhausted retries")
}

func buildPrompt(ep scanner.EntryPoint) string {
	return fmt.Sprintf(`Analyze this HTTP endpoint for SQL injection vulnerability.

Method: %s
URL: %s
Parameters: %v
Injection Location: %s

Respond ONLY with a JSON object (no markdown, no explanation outside JSON):
{
  "vulnerable": true/false,
  "confidence": 0.0-1.0,
  "payload": "suggested test payload if vulnerable, empty string if not",
  "reasoning": "one-line explanation"
}`, ep.Method, ep.URL, ep.Params, ep.InjectionLoc)
}

func callProvider(cfg config.Config, prompt string) (*AIVerdict, error) {
	client := resty.New()
	client.SetTimeout(30 * time.Second)
	client.SetHeader("Content-Type", "application/json")

	var apiURL, model string

	switch cfg.AIProvider {
	case "bedrock":
		return nil, fmt.Errorf("bedrock provider not yet implemented — use openrouter or offline mode")

	case "local":
		apiURL = "http://localhost:11434/v1/chat/completions"
		// Model name is configurable via SLEEPYWALKER_LOCAL_MODEL env var.
		// Defaults to llama3 which ships with most Ollama installations.
		model = os.Getenv("SLEEPYWALKER_LOCAL_MODEL")
		if model == "" {
			model = "llama3"
		}

	default: // "openrouter"
		apiURL = "https://openrouter.ai/api/v1/chat/completions"
		model = "gpt-4o-mini"
		client.SetHeader("Authorization", fmt.Sprintf("Bearer %s", cfg.OpenRouterAPIKey))
	}

	reqBody := openRouterRequest{
		Model:       model,
		Messages:    []Message{{Role: "user", Content: prompt}},
		MaxTokens:   300,
		Temperature: 0.1,
	}

	resp, err := client.R().
		SetBody(reqBody).
		SetResult(&openRouterResponse{}).
		Post(apiURL)

	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	if resp.IsError() {
		return nil, fmt.Errorf("API returned status %d: %s", resp.StatusCode(), resp.String())
	}

	result := resp.Result().(*openRouterResponse)
	if len(result.Choices) == 0 {
		return nil, fmt.Errorf("no choices in response")
	}

	return parseVerdict(result.Choices[0].Message.Content)
}

func parseVerdict(content string) (*AIVerdict, error) {
	var verdict AIVerdict
	cleaned := strings.TrimSpace(content)

	// Strip markdown code fences if present.
	if strings.HasPrefix(cleaned, "```") {
		lines := strings.Split(cleaned, "\n")
		var jsonLines []string
		inBlock := false
		for _, line := range lines {
			if strings.HasPrefix(line, "```") {
				inBlock = !inBlock
				continue
			}
			if inBlock {
				jsonLines = append(jsonLines, line)
			}
		}
		cleaned = strings.Join(jsonLines, "\n")
	}

	if err := json.Unmarshal([]byte(cleaned), &verdict); err == nil {
		return &verdict, nil
	}

	// Fallback: extract first JSON object found anywhere in the response.
	start := strings.Index(content, "{")
	end := strings.LastIndex(content, "}")
	if start >= 0 && end > start {
		if err := json.Unmarshal([]byte(content[start:end+1]), &verdict); err == nil {
			return &verdict, nil
		}
	}

	// Last resort: keyword matching.
	lower := strings.ToLower(content)
	if containsKeyword(lower, []string{"yes", "vulnerable", "confirmed"}) {
		return &AIVerdict{
			Vulnerable: true,
			Confidence: 0.7,
			Payload:    extractPayload(content),
			Reasoning:  "keyword-match fallback",
		}, nil
	}

	return &AIVerdict{Vulnerable: false, Confidence: 0.5, Reasoning: "could not parse AI response"}, nil
}

func containsKeyword(text string, keywords []string) bool {
	for _, k := range keywords {
		if strings.Contains(text, k) {
			return true
		}
	}
	return false
}

func extractPayload(text string) string {
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(line)), "payload:") {
			return strings.TrimSpace(line[len("payload:"):])
		}
	}
	return ""
}
