package chat

import (
	"context"
	"strings"

	"github.com/m-mizutani/goerr/v2"
	"github.com/m-mizutani/leveret/pkg/adapter"
	"google.golang.org/genai"
)

func generateTitle(ctx context.Context, gemini adapter.Gemini, message string) (string, error) {
	prompt := "Generate a short title (max 50 characters) that summarizes the following question or topic. Return only the title, nothing else:\n\n" + message

	contents := []*genai.Content{
		genai.NewContentFromText(prompt, genai.RoleUser),
	}

	resp, err := gemini.GenerateContent(ctx, contents, nil)
	if err != nil {
		return "", goerr.Wrap(err, "failed to generate title")
	}

	if len(resp.Candidates) == 0 || resp.Candidates[0].Content == nil {
		return "", goerr.New("no response from LLM")
	}

	var title strings.Builder
	for _, part := range resp.Candidates[0].Content.Parts {
		if part.Text != "" {
			title.WriteString(part.Text)
		}
	}

	// Trim whitespace and limit length
	return strings.TrimSpace(title.String()), nil
}
