package chat

import (
	"context"
	"encoding/json"

	"github.com/m-mizutani/goerr/v2"
	"github.com/m-mizutani/leveret/pkg/adapter"
	"github.com/m-mizutani/leveret/pkg/model"
	"github.com/m-mizutani/leveret/pkg/repository"
	"google.golang.org/genai"

	alerttool "github.com/m-mizutani/leveret/pkg/tool/alert"
)

// Session manages an interactive chat session for alert analysis
type Session struct {
	repo         repository.Repository
	gemini       adapter.Gemini
	storage      adapter.Storage
	alertID      model.AlertID
	alert        *model.Alert
	history      *model.History
	searchAlerts *alerttool.SearchAlerts
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
		repo:         input.Repo,
		gemini:       input.Gemini,
		storage:      input.Storage,
		alertID:      input.AlertID,
		alert:        alert,
		history:      history,
		searchAlerts: alerttool.NewSearchAlerts(input.Repo),
	}, nil
}

func (s *Session) Send(ctx context.Context, message string) (*genai.GenerateContentResponse, error) {
	if len(s.history.Contents) == 0 {
		title, err := generateTitle(ctx, s.gemini, message)
		if err != nil {
			return nil, goerr.Wrap(err, "failed to generate title")
		}
		s.history.Title = title
	}

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

	if s.searchAlerts != nil {
		config.Tools = []*genai.Tool{{
			FunctionDeclarations: []*genai.FunctionDeclaration{
				s.searchAlerts.FunctionDeclaration(),
			},
		}}
	}

	const maxIterations = 10
	var finalResp *genai.GenerateContentResponse

	for i := 0; i < maxIterations; i++ {
		resp, err := s.gemini.GenerateContent(ctx, s.history.Contents, config)
		if err != nil {
			return nil, goerr.Wrap(err, "failed to generate content")
		}
		finalResp = resp

		if len(resp.Candidates) > 0 && resp.Candidates[0].Content != nil {
			s.history.Contents = append(s.history.Contents, resp.Candidates[0].Content)
		}

		funcCalls := resp.FunctionCalls()
		if len(funcCalls) == 0 {
			break
		}

		for _, funcCall := range funcCalls {
			result, err := s.executeTool(ctx, funcCall)
			if err != nil {
				result = "Error: " + err.Error()
			}

			funcResp := &genai.FunctionResponse{
				Name:     funcCall.Name,
				Response: map[string]any{"result": result},
			}
			funcRespContent := &genai.Content{
				Role:  genai.RoleUser,
				Parts: []*genai.Part{{FunctionResponse: funcResp}},
			}
			s.history.Contents = append(s.history.Contents, funcRespContent)
		}
	}

	return finalResp, nil
}

func (s *Session) executeTool(ctx context.Context, funcCall *genai.FunctionCall) (string, error) {
	switch funcCall.Name {
	case "search_alerts":
		return s.searchAlerts.Run(ctx, funcCall.Args)
	default:
		return "", goerr.New("unknown tool", goerr.Value("name", funcCall.Name))
	}
}

func (s *Session) Save(ctx context.Context) error {
	return saveHistory(ctx, s.repo, s.storage, s.alertID, s.history)
}
