package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/cheeseandcereal/proton-cal/pkg/auth"
	"github.com/cheeseandcereal/proton-cal/pkg/config"
)

func newLoginCmd() *cobra.Command {
	var noPassphrase bool
	cmd := &cobra.Command{
		Use:   "login",
		Short: "Authenticate with Proton and save the session",
		Long: "Authenticate with Proton and save the session.\n\n" +
			"The saved session is encrypted under a passphrase you choose, which every\n" +
			"later command prompts for. Pass --no-passphrase to store it unencrypted\n" +
			"(required for the MCP server, which cannot prompt).",
		Args: requireArgs(cobra.NoArgs),
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := config.Load()
			if err != nil {
				return fmt.Errorf("loading config: %w", err)
			}
			username, err := auth.Login(cmd.Context(), auth.NewTerminalPrompter(), cfg, !noPassphrase)
			if err != nil {
				return err
			}
			// Remember the username and, on first login, the detected timezone.
			cfg.Username = username
			if cfg.Timezone == "" {
				cfg.Timezone = config.DetectTimezone()
			}
			if err := config.Save(cfg); err != nil {
				return fmt.Errorf("saving config: %w", err)
			}
			fmt.Fprintln(humanOut(), "Logged in successfully.")
			return nil
		},
	}
	cmd.Flags().BoolVar(&noPassphrase, "no-passphrase", false,
		"store the session unencrypted (needed for the MCP server; readable by any program running as you)")
	return cmd
}

func newLogoutCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "logout",
		Short: "Clear the saved session",
		Args:  requireArgs(cobra.NoArgs),
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := auth.Logout(cmd.Context(), auth.NewTerminalPrompter()); err != nil {
				return err
			}
			fmt.Fprintln(humanOut(), "Session cleared.")
			return nil
		},
	}
}
