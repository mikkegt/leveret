package alert

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"strings"
	"text/template"
	"time"
	"unicode/utf8"

	"github.com/m-mizutani/goerr/v2"
	"github.com/m-mizutani/leveret/pkg/adapter"
	"github.com/m-mizutani/leveret/pkg/model"
	"github.com/m-mizutani/leveret/pkg/utils/logging"
	"google.golang.org/genai"
)

const titleMaxLength = 100

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

	title, err := generateTitle(ctx, u.gemini, string(jsonData), titleMaxLength)
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

//go:embed prompt/title.md
var titlePromptRaw string

var titlePromptTmpl = template.Must(template.New("title").Parse(titlePromptRaw))

func generateTitle(ctx context.Context, gemini adapter.Gemini, alertData string, maxLength int) (string, error) {
	const maxRetries = 3

	var failedExamples []struct {
		Title  string
		Length int
	}
	logger := logging.From(ctx)

	for attempt := 0; attempt < maxRetries; attempt++ {
		var buf bytes.Buffer
		if err := titlePromptTmpl.Execute(&buf, map[string]any{
			"MaxLength":      maxLength,      // 最大文字数
			"AlertData":      alertData,      // アラートデータ
			"FailedExamples": failedExamples, // 過去の失敗例（リトライ時のみ）
		}); err != nil {
			return "", goerr.Wrap(err, "failed to execute title prompt template")
		}

		contents := []*genai.Content{
			{
				Role:  "user",
				Parts: []*genai.Part{{Text: buf.String()}},
			},
		}

		resp, err := gemini.GenerateContent(ctx, contents, nil)
		if err != nil {
			return "", goerr.Wrap(err, "failed to generate content for title")
		}

		if resp == nil || len(resp.Candidates) == 0 || resp.Candidates[0].Content == nil || len(resp.Candidates[0].Content.Parts) == 0 {
			return "", goerr.New("invalid response structure from gemini")
		}

		title := strings.TrimSpace(resp.Candidates[0].Content.Parts[0].Text)

		if utf8.RuneCountInString(title) <= maxLength {
			logger.Debug("title accepted", "title", title)
			return title, nil // 成功
		}

		logger.Warn("title too long, retrying", "title", title, "length", utf8.RuneCountInString(title), "maxLength", maxLength)
		failedExamples = append(failedExamples, struct {
			Title  string
			Length int
		}{title, utf8.RuneCountInString(title)})
	}

	return "", goerr.New("failed to generate title within character limit after retries")
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
