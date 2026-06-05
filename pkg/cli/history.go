package cli

import (
	"context"
	"fmt"

	"github.com/m-mizutani/goerr/v2"
	"github.com/m-mizutani/leveret/pkg/model"
	"github.com/urfave/cli/v3"
)

func historyCommand() *cli.Command {
	var (
		cfg     config
		alertID model.AlertID
	)

	flags := []cli.Flag{
		&cli.StringFlag{
			Name:        "alert-id",
			Aliases:     []string{"i"},
			Usage:       "Alert ID to list conversation histories",
			Sources:     cli.EnvVars("LEVERET_ALERT_ID"),
			Destination: (*string)(&alertID),
			Required:    true,
		},
	}
	flags = append(flags, globalFlags(&cfg)...)

	return &cli.Command{
		Name:  "history",
		Usage: "List conversation histories of a specific alert",
		Flags: flags,
		Action: func(ctx context.Context, c *cli.Command) error {
			repo, err := cfg.newRepository()
			if err != nil {
				return err
			}

			histories, err := repo.ListHistoryByAlert(ctx, alertID)
			if err != nil {
				return goerr.Wrap(err, "failed to list histories")
			}

			for _, h := range histories {
				fmt.Fprintf(c.Root().Writer, "%s\t%s\t%s\n",
					h.ID, h.CreatedAt.Format("2006-01-02 15:04:05"), h.Title)
			}
			return nil
		},
	}
}
