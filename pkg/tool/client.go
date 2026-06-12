package tool

import (
	"github.com/m-mizutani/leveret/pkg/adapter"
	"github.com/m-mizutani/leveret/pkg/repository"
)

type Client struct {
	Repo    repository.Repository
	Gemini  adapter.Gemini
	Storage adapter.Storage
}
