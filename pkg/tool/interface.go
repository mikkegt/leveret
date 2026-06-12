package tool

import (
	"context"

	"github.com/urfave/cli/v3"
	"google.golang.org/genai"
)

type Tool interface {
	Flags() []cli.Flag

	Init(ctx context.Context, client *Client) (bool, error)
	Spec() *genai.Tool
	Prompt(ctx context.Context) string
	Execute(ctx context.Context, fc genai.FunctionCall) (*genai.FunctionResponse, error)
}
