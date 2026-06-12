package alert

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/m-mizutani/goerr/v2"
	"github.com/m-mizutani/leveret/pkg/repository"
	"github.com/m-mizutani/leveret/pkg/tool"
	"github.com/urfave/cli/v3"
	"google.golang.org/genai"
)

type SearchAlerts struct {
	repo repository.Repository
}

func NewSearchAlerts() *SearchAlerts {
	return &SearchAlerts{}
}

func (s *SearchAlerts) Init(ctx context.Context, client *tool.Client) (bool, error) {
	s.repo = client.Repo
	return true, nil
}

func (s *SearchAlerts) Flags() []cli.Flag {
	return nil
}

func (s *SearchAlerts) Prompt(ctx context.Context) string {
	return ""
}

func (s *SearchAlerts) Spec() *genai.Tool {
	return &genai.Tool{
		FunctionDeclarations: []*genai.FunctionDeclaration{s.functionDeclaration()},
	}
}

func (s *SearchAlerts) functionDeclaration() *genai.FunctionDeclaration {
	return &genai.FunctionDeclaration{
		Name:        "search_alerts",
		Description: `Search alerts by querying fields in the original alert data. Field paths are automatically prefixed with "Data."`,
		Parameters: &genai.Schema{
			Type: genai.TypeObject,
			Properties: map[string]*genai.Schema{
				"field": {
					Type:        genai.TypeString,
					Description: `Field path in alert data (auto-prefixed with "Data."). Use dot notation for nested fields. The field path must exactly match the structure in the Data field of the alert. Examples: "Type", "Severity", "Service.Action.ActionType", "Resource.InstanceDetails.InstanceId"`,
				},
				"operator": {
					Type:        genai.TypeString,
					Description: "Firestore comparison operator",
					Enum:        []string{"==", "!=", "<", "<=", ">", ">=", "array-contains", "array-contains-any", "in", "not-in"},
				},
				"value": {
					Type:        genai.TypeString,
					Description: "Value to compare",
				},
				"value_type": {
					Type:        genai.TypeString,
					Description: "Type of the value (default: string)",
					Enum:        []string{"string", "number", "boolean", "array"},
				},
				"limit": {
					Type:        genai.TypeInteger,
					Description: "Max results (default: 10, max: 100)",
				},
				"offset": {
					Type:        genai.TypeInteger,
					Description: "Skip count for pagination (default: 0)",
				},
			},
			Required: []string{"field", "operator", "value"},
		},
	}
}

func (s *SearchAlerts) Execute(ctx context.Context, fc genai.FunctionCall) (*genai.FunctionResponse, error) {
	args := fc.Args
	field := args["field"].(string)
	operator := args["operator"].(string)
	value := args["value"].(string)
	value_type, ok := args["value_type"].(string)
	if !ok {
		value_type = "string"
	}
	limit := 10
	if v, ok := args["limit"].(float64); ok {
		limit = int(v)
	}
	offset := 0
	if v, ok := args["offset"].(float64); ok {
		offset = int(v)
	}

	var converted any
	var err error
	switch value_type {
	case "string":
		converted = value
	case "number":
		converted, err = strconv.ParseFloat(value, 64)
	case "boolean":
		converted, err = strconv.ParseBool(value)
	}
	if err != nil {
		return nil, goerr.Wrap(err, "failed to parse value")
	}

	alerts, err := s.repo.SearchAlerts(ctx, field, operator, converted, limit, offset)
	if err != nil {
		return nil, goerr.Wrap(err, "failed to search alerts")
	}

	var b strings.Builder
	fmt.Fprintf(&b, "Found %d alert(s):\n\n", len(alerts))

	for i, alert := range alerts {
		fmt.Fprintf(&b, "%d. ID: %s\n", i+1, alert.ID)
		fmt.Fprintf(&b, "   Title: %s\n", alert.Title)
		fmt.Fprintf(&b, "   Created: %s\n", alert.CreatedAt.Format("2006-01-02 15:04:05"))
		fmt.Fprintf(&b, "   Description: %s\n\n", alert.Description)
	}

	return &genai.FunctionResponse{
		Name:     fc.Name,
		Response: map[string]any{"result": b.String()},
	}, nil
}
