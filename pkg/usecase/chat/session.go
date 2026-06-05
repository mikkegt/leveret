package chat

import (
	"context"
	"encoding/json"

	"github.com/m-mizutani/goerr/v2"
	"github.com/m-mizutani/leveret/pkg/adapter"
	"github.com/m-mizutani/leveret/pkg/model"
	"github.com/m-mizutani/leveret/pkg/repository"
	"google.golang.org/genai"
)

// Session manages an interactive chat session for alert analysis
type Session struct {
	repo    repository.Repository
	gemini  adapter.Gemini
	storage adapter.Storage
	alertID model.AlertID
	alert   *model.Alert
	history *model.History
}

// NewInput contains parameters for creating a new chat session
type NewInput struct {
	Repo      repository.Repository
	Gemini    adapter.Gemini
	Storage   adapter.Storage
	AlertID   model.AlertID
	HistoryID *model.HistoryID // Optional: specify to continue existing conversation
}

func New(ctx context.Context, input NewInput) (*Session, error) {
	alert, err := input.Repo.GetAlert(ctx, input.AlertID)
	if err != nil {
		return nil, goerr.Wrap(err, "failed to get alert")
	}

	var history *model.History
	if input.HistoryID != nil {
		history, err = loadHistory(ctx, input.Repo, input.Storage, *input.HistoryID)
		if err != nil {
			return nil, goerr.Wrap(err, "failed to load history")
		}
	} else {
		history = &model.History{}
	}

	return &Session{
		repo:    input.Repo,
		gemini:  input.Gemini,
		storage: input.Storage,
		alertID: input.AlertID,
		alert:   alert,
		history: history,
	}, nil
}

func (s *Session) Send(ctx context.Context, message string) (*genai.GenerateContentResponse, error) {
	alertDat, err := json.MarshalIndent(s.alert.Data, "", "  ")
	if err != nil {
		return nil, goerr.Wrap(err, "failed to get history from repository")
	}

	systemPrompt := "You are a helpful assistant that analyzes alerts. The alert data is as follows:\n" + string(alertDat) + "\n"

	userContent := genai.NewContentFromText(message, genai.RoleUser)
	s.history.Contents = append(s.history.Contents, userContent)

	config := &genai.GenerateContentConfig{
		SystemInstruction: genai.NewContentFromText(systemPrompt, ""),
	}

	resp, err := s.gemini.GenerateContent(ctx, s.history.Contents, config)
	if err != nil {
		return nil, goerr.Wrap(err, "failed to generate content")
	}

	if len(resp.Candidates) > 0 && resp.Candidates[0].Content != nil {
		s.history.Contents = append(s.history.Contents, resp.Candidates[0].Content)
	}

	return resp, nil
}

func (s *Session) Save(ctx context.Context) error {
	return saveHistory(ctx, s.repo, s.storage, s.alertID, s.history)
}
