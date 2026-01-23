// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Package license provides license policy.
package license

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/denormal/go-gitignore"
	"github.com/pkg/errors"

	"github.com/siderolabs/conform/internal/policy"
)

// Licenses implement the policy.Policy interface and enforces source code license headers.
//
//nolint:recvcheck
type Licenses []License

// License represents a single license policy.
//
//nolint:govet
type License struct {
	Root string `mapstructure:"root"`
	// SkipPaths applies gitignore-style patterns to file paths to skip completely
	// parts of the tree which shouldn't be scanned (e.g. .git/)
	SkipPaths []string `mapstructure:"skipPaths"`
	// IncludeSuffixes is the regex used to find files that the license policy
	// should be applied to.
	IncludeSuffixes []string `mapstructure:"includeSuffixes"`
	// ExcludeSuffixes is the Suffixes used to find files that the license policy
	// should not be applied to.
	ExcludeSuffixes []string `mapstructure:"excludeSuffixes"`
	// AllowPrecedingComments, when enabled, allows blank lines and `//` and `#` line comments
	// before the license header. Useful for code generators that put build constraints or
	// "DO NOT EDIT" lines before the license.
	AllowPrecedingComments bool `mapstructure:"allowPrecedingComments"`
	// Header is the contents of the license header.
	Header string `mapstructure:"header"`
}

// Compliance implements the policy.Policy.Compliance function.
func (l *Licenses) Compliance(_ *policy.Options) (*policy.Report, error) {
	report := &policy.Report{}

	report.AddCheck(l.ValidateLicenseHeaders())

	return report, nil
}

// HeaderCheck enforces a license header on source code files.
type HeaderCheck struct {
	errors []error
}

// Name returns the name of the check.
func (l HeaderCheck) Name() string {
	return "File Header"
}

// Message returns to check message.
func (l HeaderCheck) Message() string {
	if len(l.errors) != 0 {
		return fmt.Sprintf("Found %d files without license header", len(l.errors))
	}

	return "All files have a valid license header"
}

// Errors returns any violations of the check.
func (l HeaderCheck) Errors() []error {
	return l.errors
}

// ValidateLicenseHeaders checks the header of a file and ensures it contains the provided value.
func (l Licenses) ValidateLicenseHeaders() policy.Check { //nolint:ireturn
	check := &HeaderCheck{}

	for _, license := range l {
		if license.Root == "" {
			license.Root = "."
		}

		check.errors = append(check.errors, validateLicenseHeader(license)...)
	}

	return check
}

//nolint:gocognit
func validateLicenseHeader(license License) []error {
	var errs []error

	var buf bytes.Buffer

	for _, pattern := range license.SkipPaths {
		fmt.Fprintf(&buf, "%s\n", pattern)
	}

	patternmatcher := gitignore.New(&buf, license.Root, func(e gitignore.Error) bool {
		errs = append(errs, e.Underlying())

		return true
	})

	if license.Header == "" {
		errs = append(errs, errors.New("Header is not defined"))

		return errs
	}

	value := []byte(strings.TrimSpace(license.Header))

	err := filepath.Walk(license.Root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if patternmatcher.Relative(path, info.IsDir()) != nil {
			if info.IsDir() {
				// skip whole directory tree
				return filepath.SkipDir
			}
			// skip single file
			return nil
		}

		if info.Mode().IsRegular() {
			// Skip excluded suffixes.
			for _, suffix := range license.ExcludeSuffixes {
				if strings.HasSuffix(info.Name(), suffix) {
					return nil
				}
			}

			// Check files matching the included suffixes.
			for _, suffix := range license.IncludeSuffixes {
				if strings.HasSuffix(info.Name(), suffix) {
					if license.AllowPrecedingComments {
						err = validateFileWithPrecedingComments(path, value)
					} else {
						err = validateFile(path, value)
					}

					if err != nil {
						errs = append(errs, err)
					}
				}
			}
		}

		return nil
	})
	if err != nil {
		errs = append(errs, errors.Errorf("Failed to walk directory: %v", err))
	}

	return errs
}

func validateFile(path string, value []byte) error {
	contents, err := os.ReadFile(path)
	if err != nil {
		return errors.Errorf("Failed to read %s: %s", path, err)
	}

	if bytes.HasPrefix(contents, value) {
		return nil
	}

	return errors.Errorf("File %s does not contain a license header", path)
}

func validateFileWithPrecedingComments(path string, value []byte) error {
	contents, err := os.ReadFile(path)
	if err != nil {
		return errors.Errorf("Failed to read %s: %s", path, err)
	}

	prefix := extractCommentPrefix(contents)
	if bytes.Contains(prefix, value) {
		return nil
	}

	return errors.Errorf("File %s does not contain a license header", path)
}

// Fix implements the policy.Fixer interface.
func (l *Licenses) Fix() (*policy.FixReport, error) {
	report := &policy.FixReport{}

	for _, license := range *l {
		if license.Root == "" {
			license.Root = "."
		}

		results := fixLicenseHeaders(license)
		report.Results = append(report.Results, results...)
	}

	return report, nil
}

//nolint:gocognit
func fixLicenseHeaders(license License) []policy.FixResult {
	var results []policy.FixResult

	var buf bytes.Buffer

	for _, pattern := range license.SkipPaths {
		fmt.Fprintf(&buf, "%s\n", pattern)
	}

	patternmatcher := gitignore.New(&buf, license.Root, func(e gitignore.Error) bool {
		results = append(results, policy.FixResult{
			Path:  license.Root,
			Error: e.Underlying(),
		})

		return true
	})

	if license.Header == "" {
		results = append(results, policy.FixResult{
			Path:  license.Root,
			Error: errors.New("Header is not defined"),
		})

		return results
	}

	header := []byte(strings.TrimSpace(license.Header))

	err := filepath.Walk(license.Root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if patternmatcher.Relative(path, info.IsDir()) != nil {
			if info.IsDir() {
				return filepath.SkipDir
			}

			return nil
		}

		if info.Mode().IsRegular() {
			// Skip excluded suffixes.
			for _, suffix := range license.ExcludeSuffixes {
				if strings.HasSuffix(info.Name(), suffix) {
					return nil
				}
			}

			// Check files matching the included suffixes.
			for _, suffix := range license.IncludeSuffixes {
				if strings.HasSuffix(info.Name(), suffix) {
					result := fixFile(path, header, license.AllowPrecedingComments)
					if result.NewContents != nil || result.Skipped || result.Error != nil {
						results = append(results, result)
					}
				}
			}
		}

		return nil
	})
	if err != nil {
		results = append(results, policy.FixResult{
			Path:  license.Root,
			Error: errors.Errorf("Failed to walk directory: %v", err),
		})
	}

	return results
}

func fixFile(path string, header []byte, allowPreceding bool) policy.FixResult {
	contents, err := os.ReadFile(path)
	if err != nil {
		return policy.FixResult{
			Path:  path,
			Error: errors.Errorf("Failed to read %s: %s", path, err),
		}
	}

	// Check if the file already has the header
	if allowPreceding {
		if fileHasHeaderWithPrecedingComments(contents, header) {
			return policy.FixResult{Path: path}
		}
	} else {
		if bytes.HasPrefix(contents, header) {
			return policy.FixResult{Path: path}
		}
	}

	// File needs fixing
	hasShebang, shebangEnd := detectShebang(contents)

	if hasShebang && !allowPreceding {
		return policy.FixResult{
			Path:       path,
			Skipped:    true,
			SkipReason: "file has shebang but allowPrecedingComments is false",
		}
	}

	// Build the new file contents
	var newContents []byte

	if hasShebang {
		// Insert header after shebang line
		newContents = append(newContents, contents[:shebangEnd]...)
		newContents = append(newContents, header...)
		newContents = append(newContents, '\n')
		newContents = append(newContents, contents[shebangEnd:]...)
	} else {
		// Insert header at file start
		newContents = append(newContents, header...)
		newContents = append(newContents, '\n')
		newContents = append(newContents, contents...)
	}

	return policy.FixResult{
		Path:        path,
		OldContents: contents,
		NewContents: newContents,
	}
}

func detectShebang(content []byte) (hasShebang bool, endOffset int) {
	if !bytes.HasPrefix(content, []byte("#!")) {
		return false, 0
	}

	// Find the end of the first line
	idx := bytes.IndexByte(content, '\n')
	if idx == -1 {
		// Entire file is the shebang line
		return true, len(content)
	}

	return true, idx + 1
}

// isCommentLine checks if a line (trimmed of whitespace) is a comment or blank line.
func isCommentLine(line string) bool {
	return line == "" || strings.HasPrefix(line, "//") || strings.HasPrefix(line, "#")
}

// extractCommentPrefix scans file contents and returns all leading comment lines.
func extractCommentPrefix(contents []byte) []byte {
	var prefix []byte

	scanner := bufio.NewScanner(bytes.NewReader(contents))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !isCommentLine(line) {
			break
		}

		prefix = append(prefix, scanner.Bytes()...)
		prefix = append(prefix, '\n')
	}

	return prefix
}

func fileHasHeaderWithPrecedingComments(contents []byte, header []byte) bool {
	prefix := extractCommentPrefix(contents)

	return bytes.Contains(prefix, header)
}
