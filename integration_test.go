package main

import (
	"io"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

type integrationTest struct {
	name           string
	expectPanic    bool
	flags          []string
	expectedOutput string
}

func TestRun(t *testing.T) {
	tests := []integrationTest{
		{
			name:           "Validate flux2-install",
			expectPanic:    false,
			flags:          []string{"-f", "tests/flux2-install.yaml", "-l", "debug"},
			expectedOutput: "total: 38, Invalid: 0\n",
		},
		{
			name:           "Validate invalid-metadata",
			expectPanic:    true,
			flags:          []string{"-f", "tests/invalid-metadata.yaml", "-l", "debug"},
			expectedOutput: "total: 4, Invalid: 2\n",
		},
		{
			name:           "Validate invalid-metadata but with allow-failure",
			expectPanic:    false,
			flags:          []string{"-f", "tests/invalid-metadata.yaml", "-l", "debug", "--allow-failure=true"},
			expectedOutput: "total: 4, Invalid: 2\n",
		},
		{
			name:           "Validate without-namespace",
			expectPanic:    false,
			flags:          []string{"-f", "tests/without-namespace.yaml", "-l", "debug"},
			expectedOutput: "total: 2, Invalid: 0\n",
		},
		{
			name:           "Validate without-namespace but with --skip-auto-namespace",
			expectPanic:    true,
			flags:          []string{"-f", "tests/without-namespace.yaml", "-l", "debug", "--skip-auto-namespace=true"},
			expectedOutput: "total: 1, Invalid: 1\n",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			executeIntegrationTest(t, test)
		})
	}
}

func executeIntegrationTest(t *testing.T, test integrationTest) {
	f, err := os.CreateTemp(os.TempDir(), "yakmv-testing")
	assert.NoError(t, err)
	output = f

	os.Args = append([]string{"yakmv"}, test.flags...)

	if test.expectPanic {
		assert.Panics(t, func() { main() })
	} else {
		main()
	}

	_, err = f.Seek(0, 0)
	assert.NoError(t, err)
	b, err := io.ReadAll(f)
	assert.NoError(t, err)
	assert.Equal(t, test.expectedOutput, string(b))
}
