// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package main

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/siderolabs/conform/internal/enforcer"
)

// formatCmd represents the format command.
var formatCmd = &cobra.Command{
	Use:   "format",
	Short: "Fix autofixable policy violations",
	Long:  `Automatically fixes policy violations that can be auto-corrected, such as adding missing license headers.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) != 0 {
			return errors.New("the format command does not take arguments")
		}
		// Done validating the arguments, do not print usage for errors
		// after this point
		cmd.SilenceUsage = true

		// Get the config path value
		configPath := cmd.Flags().Lookup("config").Value.String()
		e, err := enforcer.New(configPath, "none")
		if err != nil {
			return fmt.Errorf("failed to create enforcer: %w", err)
		}

		diff, err := cmd.Flags().GetBool("diff")
		if err != nil {
			return fmt.Errorf("failed to get diff flag: %w", err)
		}

		return e.Format(diff)
	},
}

func init() {
	formatCmd.Flags().String("config", ".conform.yaml", "config file path")
	formatCmd.Flags().Bool("diff", false, "show what would change without writing files")
	rootCmd.AddCommand(formatCmd)
}
