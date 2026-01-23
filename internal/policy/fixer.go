// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package policy

// FixResult represents the result of fixing a single file.
//
//nolint:govet
type FixResult struct {
	OldContents []byte
	NewContents []byte
	Path        string
	SkipReason  string
	Error       error
	Skipped     bool
}

// FixReport contains the results of a fix operation.
type FixReport struct {
	Results []FixResult
}

// Fixer is an interface that policies can implement to support auto-fixing violations.
type Fixer interface {
	Fix() (*FixReport, error)
}
