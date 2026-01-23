// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Package enforcer defines policy enforcement.
package enforcer

import (
	"fmt"
	"log"
	"os"
	"text/tabwriter"

	"github.com/mitchellh/mapstructure"
	"github.com/pkg/errors"
	"github.com/pmezard/go-difflib/difflib"
	yaml "gopkg.in/yaml.v3"

	"github.com/siderolabs/conform/internal/policy"
	"github.com/siderolabs/conform/internal/policy/commit"
	"github.com/siderolabs/conform/internal/policy/license"
	"github.com/siderolabs/conform/internal/reporter"
)

// Conform is a struct that conform.yaml gets decoded into.
//
//nolint:govet
type Conform struct {
	Policies []*PolicyDeclaration `yaml:"policies"`
	reporter reporter.Reporter
}

// PolicyDeclaration allows a user to declare an arbitrary type along with a
// spec that will be decoded into the appropriate concrete type.
//
//nolint:govet
type PolicyDeclaration struct {
	Type string `yaml:"type"`
	Spec any    `yaml:"spec"`
}

// New loads the conform.yaml file and unmarshals it into a Conform struct.
func New(cp string, r string) (*Conform, error) {
	c := &Conform{}

	switch r {
	case "github":
		s, err := reporter.NewGitHubReporter()
		if err != nil {
			return nil, err
		}

		c.reporter = s
	default:
		c.reporter = &reporter.Noop{}
	}

	configBytes, err := os.ReadFile(cp)
	if err != nil {
		return nil, err
	}

	err = yaml.Unmarshal(configBytes, c)
	if err != nil {
		return nil, err
	}

	return c, nil
}

// Enforce enforces all policies defined in the conform.yaml file.
func (c *Conform) Enforce(setters ...policy.Option) error {
	opts := policy.NewDefaultOptions(setters...)

	const padding = 8

	w := tabwriter.NewWriter(os.Stdout, 0, 0, padding, ' ', 0)
	fmt.Fprintln(w, "POLICY\tCHECK\tSTATUS\tMESSAGE\t") //nolint:errcheck

	pass := true

	policiesWithTypes, err := c.convertDeclarations()
	if err != nil {
		return fmt.Errorf("failed to convert declarations: %w", err)
	}

	for _, p := range policiesWithTypes {
		report, err := p.policy.Compliance(opts)
		if err != nil {
			log.Fatal(err)
		}

		for _, check := range report.Checks() {
			if len(check.Errors()) != 0 {
				for _, err := range check.Errors() {
					fmt.Fprintf(w, "%s\t%s\t%s\t%v\t\n", p.Type, check.Name(), "FAILED", err) //nolint:errcheck
				}

				if err := c.reporter.SetStatus("failure", p.Type, check.Name(), check.Message()); err != nil {
					log.Printf("WARNING: report failed: %+v", err)
				}

				pass = false
			} else {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t\n", p.Type, check.Name(), "PASS", check.Message()) //nolint:errcheck

				if err := c.reporter.SetStatus("success", p.Type, check.Name(), check.Message()); err != nil {
					log.Printf("WARNING: report failed: %+v", err)
				}
			}
		}
	}

	w.Flush() //nolint:errcheck

	if !pass {
		return errors.New("1 or more policy failed")
	}

	return nil
}

type policyWithType struct {
	policy policy.Policy
	Type   string
}

// Format applies fixes for all policies that implement the Fixer interface.
func (c *Conform) Format(dryRun bool) error {
	policiesWithTypes, err := c.convertDeclarations()
	if err != nil {
		return fmt.Errorf("failed to convert declarations: %w", err)
	}

	hasChanges := false
	hasErrors := false

	for _, p := range policiesWithTypes {
		fixer, ok := p.policy.(policy.Fixer)
		if !ok {
			continue
		}

		report, err := fixer.Fix()
		if err != nil {
			log.Printf("ERROR: %s fix failed: %v", p.Type, err)

			hasErrors = true

			continue
		}

		for _, result := range report.Results {
			switch {
			case result.Error != nil:
				fmt.Printf("ERROR %s: %v\n", result.Path, result.Error)

				hasErrors = true
			case result.Skipped:
				fmt.Printf("SKIP  %s: %s\n", result.Path, result.SkipReason)
			case result.NewContents != nil:
				if dryRun {
					diffText, err := generateDiff(result.Path, result.OldContents, result.NewContents)
					if err != nil {
						fmt.Printf("ERROR %s: %v\n", result.Path, err)

						hasErrors = true

						continue
					}

					fmt.Print(diffText)
				} else {
					if err := os.WriteFile(result.Path, result.NewContents, 0o644); err != nil {
						fmt.Printf("ERROR %s: %v\n", result.Path, err)

						hasErrors = true

						continue
					}

					fmt.Printf("FIXED %s\n", result.Path)
				}

				hasChanges = true
			}
		}
	}

	if hasErrors {
		return errors.New("1 or more files failed to fix")
	}

	if dryRun && hasChanges {
		return errors.New("files need formatting")
	}

	return nil
}

func generateDiff(path string, original, modified []byte) (string, error) {
	diff := difflib.UnifiedDiff{
		A:        difflib.SplitLines(string(original)),
		B:        difflib.SplitLines(string(modified)),
		FromFile: "a/" + path,
		ToFile:   "b/" + path,
		Context:  3,
	}

	text, err := difflib.GetUnifiedDiffString(diff)
	if err != nil {
		return "", errors.Errorf("generating diff for %s: %v", path, err)
	}

	return text, nil
}

func (c *Conform) convertDeclarations() ([]policyWithType, error) {
	const typeLicense = "license"

	var (
		policies = make([]policyWithType, 0, len(c.Policies))
		licenses = make(license.Licenses, 0, len(c.Policies))
	)

	for _, p := range c.Policies {
		switch p.Type {
		case typeLicense:
			var lcs license.License

			if err := mapstructure.Decode(p.Spec, &lcs); err != nil {
				return nil, fmt.Errorf("failed to convert license policy: %w", err)
			}

			licenses = append(licenses, lcs)

		case "commit":
			// backwards compatibility, convert `gpg: bool` into `gpg: required: bool`
			if spec, ok := p.Spec.(map[any]any); ok {
				if gpg, ok := spec["gpg"]; ok {
					if val, ok := gpg.(bool); ok {
						spec["gpg"] = map[string]any{
							"required": val,
						}
					}
				}
			}

			var cmt commit.Commit

			if err := mapstructure.Decode(p.Spec, &cmt); err != nil {
				return nil, fmt.Errorf("failed to convert commit policy: %w", err)
			}

			policies = append(policies, policyWithType{
				Type:   p.Type,
				policy: &cmt,
			})
		default:
			return nil, fmt.Errorf("invalid policy type: %s", p.Type)
		}
	}

	policies = append(policies, policyWithType{
		Type:   typeLicense,
		policy: &licenses,
	})

	return policies, nil
}
