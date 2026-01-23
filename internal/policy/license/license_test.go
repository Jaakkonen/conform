// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build !some_test_tag

package license_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/siderolabs/conform/internal/policy/license"
)

func TestLicense(t *testing.T) {
	const header = `
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.`

	const otherHeader = "// some-other-header"

	t.Run("Default", func(t *testing.T) {
		l := license.Licenses{
			{
				SkipPaths:              []string{"subdir1/"},
				IncludeSuffixes:        []string{".txt"},
				AllowPrecedingComments: false,
				Header:                 header,
			},
		}
		check := l.ValidateLicenseHeaders()
		assert.Equal(t, "Found 1 files without license header", check.Message())
	})

	t.Run("AllowPrecedingComments", func(t *testing.T) {
		l := license.Licenses{
			{
				SkipPaths:              []string{"subdir1/"},
				IncludeSuffixes:        []string{".txt"},
				AllowPrecedingComments: true,
				Header:                 header,
			},
		}
		check := l.ValidateLicenseHeaders()
		assert.Equal(t, "All files have a valid license header", check.Message())
	})

	// File "testdata/subdir1/subdir2/data.txt" is valid for the root license, but "testdata/subdir1/" is skipped.
	// It is invalid for the additional license, but that license skips "subdir2/" relative to itself.
	// The check should pass.
	t.Run("AdditionalValid", func(t *testing.T) {
		l := license.Licenses{
			{
				IncludeSuffixes:        []string{".txt"},
				SkipPaths:              []string{"testdata/subdir1/"},
				AllowPrecedingComments: true,
				Header:                 header,
			},
			{
				Root:            "testdata/subdir1/",
				SkipPaths:       []string{"subdir2/"},
				IncludeSuffixes: []string{".txt"},
				Header:          otherHeader,
			},
		}
		check := l.ValidateLicenseHeaders()
		assert.Equal(t, "All files have a valid license header", check.Message())
	})

	// File "testdata/subdir1/subdir2/data.txt" is valid for the root license, but "testdata/subdir1/" is skipped.
	// However, it is invalid for the additional license.
	// The check should fail.
	t.Run("AdditionalInvalid", func(t *testing.T) {
		l := license.Licenses{
			{
				IncludeSuffixes:        []string{".txt"},
				SkipPaths:              []string{"testdata/subdir1/"},
				AllowPrecedingComments: true,
				Header:                 header,
			},

			{
				Root:            "testdata/subdir1/",
				IncludeSuffixes: []string{".txt"},
				Header:          otherHeader,
			},
		}
		check := l.ValidateLicenseHeaders()
		assert.Equal(t, "Found 1 files without license header", check.Message())
	})
}

func TestLicenseFix(t *testing.T) {
	const header = `// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.`

	t.Run("FileWithoutHeader", func(t *testing.T) {
		tmpDir := t.TempDir()
		testFile := filepath.Join(tmpDir, "test.go")
		require.NoError(t, os.WriteFile(testFile, []byte("package main\n"), 0o644))

		l := license.Licenses{
			{
				Root:            tmpDir,
				IncludeSuffixes: []string{".go"},
				Header:          header,
			},
		}

		report, err := l.Fix()
		require.NoError(t, err)
		require.Len(t, report.Results, 1)

		result := report.Results[0]
		assert.Equal(t, testFile, result.Path)
		assert.NotNil(t, result.NewContents)
		assert.Contains(t, string(result.NewContents), "mozilla.org/MPL/2.0")
		assert.Contains(t, string(result.NewContents), "package main")
	})

	t.Run("FileWithShebangAndAllowPreceding", func(t *testing.T) {
		tmpDir := t.TempDir()
		testFile := filepath.Join(tmpDir, "test.sh")
		require.NoError(t, os.WriteFile(testFile, []byte("#!/bin/bash\necho hello\n"), 0o644))

		l := license.Licenses{
			{
				Root:                   tmpDir,
				IncludeSuffixes:        []string{".sh"},
				AllowPrecedingComments: true,
				Header:                 header,
			},
		}

		report, err := l.Fix()
		require.NoError(t, err)
		require.Len(t, report.Results, 1)

		result := report.Results[0]
		assert.NotNil(t, result.NewContents)
		assert.True(t, string(result.NewContents[:11]) == "#!/bin/bash", "shebang should be first")
		assert.Contains(t, string(result.NewContents), "mozilla.org/MPL/2.0")
		assert.Contains(t, string(result.NewContents), "echo hello")
	})

	t.Run("FileWithShebangWithoutAllowPreceding", func(t *testing.T) {
		tmpDir := t.TempDir()
		testFile := filepath.Join(tmpDir, "test.sh")
		require.NoError(t, os.WriteFile(testFile, []byte("#!/bin/bash\necho hello\n"), 0o644))

		l := license.Licenses{
			{
				Root:                   tmpDir,
				IncludeSuffixes:        []string{".sh"},
				AllowPrecedingComments: false,
				Header:                 header,
			},
		}

		report, err := l.Fix()
		require.NoError(t, err)
		require.Len(t, report.Results, 1)

		result := report.Results[0]
		assert.True(t, result.Skipped)
		assert.Contains(t, result.SkipReason, "shebang")
		assert.Nil(t, result.NewContents)
	})

	t.Run("FileAlreadyHasHeader", func(t *testing.T) {
		tmpDir := t.TempDir()
		testFile := filepath.Join(tmpDir, "test.go")
		contentWithHeader := header + "\n\npackage main\n"
		require.NoError(t, os.WriteFile(testFile, []byte(contentWithHeader), 0o644))

		l := license.Licenses{
			{
				Root:            tmpDir,
				IncludeSuffixes: []string{".go"},
				Header:          header,
			},
		}

		report, err := l.Fix()
		require.NoError(t, err)
		assert.Empty(t, report.Results)
	})

	t.Run("ReturnsOldAndNewContents", func(t *testing.T) {
		tmpDir := t.TempDir()
		testFile := filepath.Join(tmpDir, "test.go")
		originalContent := "package main\n"
		require.NoError(t, os.WriteFile(testFile, []byte(originalContent), 0o644))

		l := license.Licenses{
			{
				Root:            tmpDir,
				IncludeSuffixes: []string{".go"},
				Header:          header,
			},
		}

		report, err := l.Fix()
		require.NoError(t, err)
		require.Len(t, report.Results, 1)

		result := report.Results[0]
		assert.Equal(t, []byte(originalContent), result.OldContents)
		assert.NotNil(t, result.NewContents)
		assert.NotEqual(t, result.OldContents, result.NewContents)
	})
}
