package alert

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/m-mizutani/goerr/v2"
	"github.com/m-mizutani/leveret/pkg/adapter"
	"github.com/m-mizutani/leveret/pkg/model"
	"google.golang.org/genai"
)

func (u *UseCase) Insert(
	ctx context.Context,
	data any,
) (*model.Alert, error) {
	alert := &model.Alert{
		ID:        model.NewAlertID(),
		Data:      data,
		CreatedAt: time.Now(),
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		return nil, goerr.Wrap(err, "failed to marshal alert data")
	}

	title, err := generateTitle(ctx, u.gemini, string(jsonData))
	if err != nil {
		return nil, goerr.Wrap(err, "failed to generate title")
	}
	alert.Title = title

	description, err := generateDescription(ctx, u.gemini, string(jsonData))
	if err != nil {
		return nil, goerr.Wrap(err, "failed to generate description")
	}
	alert.Description = description

	if err := u.repo.PutAlert(ctx, alert); err != nil {
		return nil, err
	}

	return alert, nil
}

func generateTitle(ctx context.Context, gemini adapter.Gemini, alertData string) (string, error) {
	prompt := "このセキュリティ警告の短いタイトル（100文字未満）を生成してください。説明は含めず、タイトルのみを返してください。\n\n" + alertData

	contents := []*genai.Content{
		{
			Role:  "user",
			Parts: []*genai.Part{{Text: prompt}},
		},
	}

	resp, err := gemini.GenerateContent(ctx, contents, nil)
	if err != nil {
		return "", goerr.Wrap(err, "failed to generate content for title")
	}

	if resp == nil || len(resp.Candidates) == 0 || resp.Candidates[0].Content == nil || len(resp.Candidates[0].Content.Parts) == 0 {
		return "", goerr.New("invalid response structure from gemini")
	}

	return strings.TrimSpace(resp.Candidates[0].Content.Parts[0].Text), nil
}

func generateDescription(ctx context.Context, gemini adapter.Gemini, alertData string) (string, error) {
	prompt := "このセキュリティアラートについて、詳細な説明（2～3文）を作成してください。何が起こったのか、なぜそれが重要なのかを説明してください。前置きや補足は付けず、説明文のみを返してください。\n\n" + alertData
	contents := []*genai.Content{
		{
			Role:  "user",
			Parts: []*genai.Part{{Text: prompt}},
		},
	}

	resp, err := gemini.GenerateContent(ctx, contents, nil)
	if err != nil {
		return "", goerr.Wrap(err, "failed to generate content for description")
	}

	if resp == nil || len(resp.Candidates) == 0 || resp.Candidates[0].Content == nil || len(resp.Candidates[0].Content.Parts) == 0 {
		return "", goerr.New("invalid response structure from gemini")
	}

	return strings.TrimSpace(resp.Candidates[0].Content.Parts[0].Text), nil
}
