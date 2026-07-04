package tool

import (
	"context"
	"strings"

	"github.com/m-mizutani/goerr/v2"
	"github.com/urfave/cli/v3"
	"google.golang.org/genai"
)

type Registry struct {
	tools        map[string]Tool
	allTools     []Tool
	enabledTools []Tool
	toolSpecs    map[*genai.Tool]bool
}

var errToolNotFound = goerr.New("tool not found")

func NewRegistry(tools ...Tool) *Registry {
	r := &Registry{
		tools:     make(map[string]Tool),
		allTools:  tools,
		toolSpecs: make(map[*genai.Tool]bool),
	}

	return r
}

func (r *Registry) Flags() []cli.Flag {
	var flags []cli.Flag
	for _, t := range r.allTools {
		if toolFlags := t.Flags(); toolFlags != nil {
			flags = append(flags, toolFlags...)
		}
	}
	return flags
}

func (r *Registry) Init(ctx context.Context, client *Client) error {
	for _, t := range r.allTools {
		enabled, err := t.Init(ctx, client)
		if err != nil {
			return goerr.Wrap(err, "failed to initialize tool")
		}

		if !enabled {
			continue
		}

		r.enabledTools = append(r.enabledTools, t)

		spec := t.Spec()
		if spec == nil || len(spec.FunctionDeclarations) == 0 {
			continue
		}

		r.toolSpecs[spec] = true

		for _, fd := range spec.FunctionDeclarations {
			if existing, exists := r.tools[fd.Name]; exists {
				if existing != t {
					return goerr.New("duplicate function name", goerr.V("name", fd.Name))
				}
				continue
			}
			r.tools[fd.Name] = t
		}
	}
	return nil
}

func (r *Registry) Specs() []*genai.Tool {
	if len(r.toolSpecs) == 0 {
		return nil
	}

	var allDeclarations []*genai.FunctionDeclaration
	for spec := range r.toolSpecs {
		if spec.FunctionDeclarations != nil {
			allDeclarations = append(allDeclarations, spec.FunctionDeclarations...)
		}
	}

	if len(allDeclarations) == 0 {
		return nil
	}

	return []*genai.Tool{
		{
			FunctionDeclarations: allDeclarations,
		},
	}
}

func (r *Registry) Prompts(ctx context.Context) string {
	var prompts []string
	for _, t := range r.enabledTools {
		if prompt := t.Prompt(ctx); prompt != "" {
			prompts = append(prompts, prompt)
		}
	}
	return strings.Join(prompts, "\n\n")
}

func (r *Registry) Execute(ctx context.Context, fc genai.FunctionCall) (*genai.FunctionResponse, error) {
	tool, ok := r.tools[fc.Name]
	if !ok {
		return nil, goerr.Wrap(errToolNotFound, "tool not found", goerr.Value("name", fc.Name))
	}
	return tool.Execute(ctx, fc)
}

func (r *Registry) EnabledTools() []string {
	tools := make([]string, 0, len(r.tools))
	for name := range r.tools {
		tools = append(tools, name)
	}
	return tools
}
