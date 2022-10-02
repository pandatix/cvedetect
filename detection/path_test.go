package detection_test

import (
	"testing"

	"github.com/pandatix/cvedetect/detection"
	"github.com/stretchr/testify/assert"
)

func ptr[T any](t T) *T {
	return &t
}

var testsNode = map[string]struct {
	Node   *detection.Node
	String string
}{
	"one-node-one-matcher": {
		// This case is the most common one: it represents a MDC=1 Circuit that
		// matches on only one Matcher.
		// It's the case where no version bound is defined, so is a TLC.
		Node: &detection.Node{
			Operator: "OR",
			Children: nil,
			Matchers: []*detection.Matcher{
				{
					SuperCPE23:            "cpe:2.3:a:fake:asset:*:*:*:*:*:*:*:*",
					SubCPE23:              "cpe:2.3:a:fake:asset:5:*:*:*:*:*:*:*",
					Vulnerable:            true,
					VersionStartIncluding: nil,
					VersionStartExcluding: nil,
					VersionEndIncluding:   nil,
					VersionEndExcluding:   nil,
				},
			},
		},
		String: `(|(v cpe:2.3:a:fake:asset:*:*:*:*:*:*:*:* incl cpe:2.3:a:fake:asset:5:*:*:*:*:*:*:* ,  , ))`,
	},
	"one-node-one-matcher-version-interval": {
		// This case is the most common one: it represents a MDC=1 Circuit that
		// matches on only one Matcher.
		// It's the case where SuperCPE23 has no other specific field defined
		// (one of version, update, edition, sw_edition, language, target_sw,
		// target_hw and other) and version bounds.
		Node: &detection.Node{
			Operator: "OR",
			Children: nil,
			Matchers: []*detection.Matcher{
				{
					SuperCPE23:            "cpe:2.3:a:fake:asset:*:*:*:*:*:*:*:*",
					SubCPE23:              "cpe:2.3:a:fake:asset:2:u2:*:*:*:*:*:*",
					Vulnerable:            true,
					VersionStartIncluding: nil,
					VersionStartExcluding: nil,
					VersionEndIncluding:   nil,
					VersionEndExcluding:   ptr("3.5.7"),
				},
			},
		},
		String: `(|(v cpe:2.3:a:fake:asset:*:*:*:*:*:*:*:* incl cpe:2.3:a:fake:asset:2:u2:*:*:*:*:*:* ,  , < 3.5.7))`,
	},
	"one-node-one-matcher-supercpe23": {
		// This case is common but not prevalent: it represents a MDC=1 Circuit
		// that matches on only one Matcher.
		// It's the case where there are no version bounds, everything is defined
		// in the SuperCPE23. This often comes from an enumeration when the vendor
		// versionning strategy uses updates, languages...etc.
		Node: &detection.Node{
			Operator: "OR",
			Children: nil,
			Matchers: []*detection.Matcher{
				{
					SuperCPE23:            "cpe:2.3:a:fake:asset:2:u2:*:*:*:*:x86:*",
					SubCPE23:              "cpe:2.3:a:fake:asset:2:u2:*:*:*:*:x86:*",
					Vulnerable:            true,
					VersionStartIncluding: nil,
					VersionStartExcluding: nil,
					VersionEndIncluding:   nil,
					VersionEndExcluding:   nil,
				},
			},
		},
		String: `(|(v cpe:2.3:a:fake:asset:2:u2:*:*:*:*:x86:* incl cpe:2.3:a:fake:asset:2:u2:*:*:*:*:x86:* ,  , ))`,
	},
	"and-or-version-interval": {
		// This case is an unrealistic one, but representing a possible Circuit
		// for MDC>1.
		Node: &detection.Node{
			Operator: "AND",
			Children: []*detection.Node{
				{
					Operator: "OR",
					Children: nil,
					Matchers: []*detection.Matcher{
						{
							SuperCPE23:            "cpe:2.3:a:gitea:gitea:*:*:*:*:*:*:*:*",
							SubCPE23:              "cpe:2.3:a:gitea:gitea:1\\.12\\.6:*:*:*:*:docker:*:*",
							Vulnerable:            true,
							VersionStartIncluding: ptr("1.12.0"),
							VersionStartExcluding: nil,
							VersionEndIncluding:   ptr("1.12.6"),
							VersionEndExcluding:   nil,
						}, {
							SuperCPE23:            "cpe:2.3:a:gitea:gitea:*:*:*:*:*:*:*:*",
							SubCPE23:              "cpe:2.3:a:gitea:gitea:1\\.13\\.2:*:*:*:*:docker:*:*",
							Vulnerable:            false,
							VersionStartIncluding: ptr("1.13.0"),
							VersionStartExcluding: nil,
							VersionEndIncluding:   nil,
							VersionEndExcluding:   ptr("1.13.4"),
						},
					},
				}, {
					Operator: "OR",
					Children: nil,
					Matchers: []*detection.Matcher{
						{
							SuperCPE23:            "cpe:2.3:a:gitea:gitea:*:*:*:*:*:docker:*:*",
							SubCPE23:              "cpe:2.3:a:gitea:gitea:1\\.12\\.6:*:*:*:*:*:*:*",
							Vulnerable:            true,
							VersionStartIncluding: nil,
							VersionStartExcluding: nil,
							VersionEndIncluding:   nil,
							VersionEndExcluding:   nil,
						},
					},
				},
			},
			Matchers: nil,
		},
		String: `(&(|(v cpe:2.3:a:gitea:gitea:*:*:*:*:*:*:*:* incl cpe:2.3:a:gitea:gitea:1\.12\.6:*:*:*:*:docker:*:* , 1.12.0 <= , <= 1.12.6)(i cpe:2.3:a:gitea:gitea:*:*:*:*:*:*:*:* incl cpe:2.3:a:gitea:gitea:1\.13\.2:*:*:*:*:docker:*:* , 1.13.0 <= , < 1.13.4))(|(v cpe:2.3:a:gitea:gitea:*:*:*:*:*:docker:*:* incl cpe:2.3:a:gitea:gitea:1\.12\.6:*:*:*:*:*:*:* ,  , )))`,
	},
	"negative-circuit": {
		// This case shows how to use a Circuit to represent a non-matching
		// Configuration.
		// The analyst must understand that all the verbose information given
		// by the Circuit string is invalid: it did not match, so don't try
		// to understand what info it gives, because it means nothing.
		Node: &detection.Node{
			Operator: "OR",
			Children: nil,
			Matchers: []*detection.Matcher{
				{
					SuperCPE23:            "cpe:2.3:a:gitea:gitea:*:*:*:*:*:docker:*:*",
					SubCPE23:              "cpe:2.3:a:docker:docker:19.03.15:*:*:*:*:linux:amd64:*",
					Vulnerable:            true,
					VersionStartIncluding: ptr("1.12.0"),
					VersionStartExcluding: nil,
					VersionEndIncluding:   nil,
					VersionEndExcluding:   ptr("1.12.6"),
				},
			},
		},
		String: "(|(v cpe:2.3:a:gitea:gitea:*:*:*:*:*:docker:*:* incl cpe:2.3:a:docker:docker:19.03.15:*:*:*:*:linux:amd64:* , 1.12.0 <= , < 1.12.6))",
	},
}

var testsMatcher = map[string]struct {
	Matcher *detection.Matcher
	String  string
}{
	"standard-matcher": {
		String: "(v cpe:2.3:a:gitea:gitea:*:*:*:*:*:*:*:* incl cpe:2.3:a:gitea:gitea:1\\.12\\.4:*:*:*:*:*:*:* , 1.12.0 <= , < 1.12.6)",
		Matcher: &detection.Matcher{
			SuperCPE23:            "cpe:2.3:a:gitea:gitea:*:*:*:*:*:*:*:*",
			SubCPE23:              "cpe:2.3:a:gitea:gitea:1\\.12\\.4:*:*:*:*:*:*:*",
			Vulnerable:            true,
			VersionStartIncluding: ptr("1.12.0"),
			VersionStartExcluding: nil,
			VersionEndIncluding:   nil,
			VersionEndExcluding:   ptr("1.12.6"),
		},
	},
	"no-version-bounds": {
		String: "(v cpe:2.3:a:gitea:gitea:*:*:*:*:*:*:*:* incl cpe:2.3:a:gitea:gitea:1\\.12\\.4:*:*:*:*:*:*:* ,  , )",
		Matcher: &detection.Matcher{
			SuperCPE23:            "cpe:2.3:a:gitea:gitea:*:*:*:*:*:*:*:*",
			SubCPE23:              "cpe:2.3:a:gitea:gitea:1\\.12\\.4:*:*:*:*:*:*:*",
			Vulnerable:            true,
			VersionStartIncluding: nil,
			VersionStartExcluding: nil,
			VersionEndIncluding:   nil,
			VersionEndExcluding:   nil,
		},
	},
}

func TestNodeString(t *testing.T) {
	t.Parallel()

	// Actual test
	for testname, tt := range testsNode {
		t.Run(testname, func(t *testing.T) {
			assert := assert.New(t)

			str := tt.Node.String()

			assert.Equal(tt.String, str)
		})
	}
}

func TestParseNode(t *testing.T) {
	t.Parallel()

	// Prepare specific and common tests
	type test struct {
		Input        string
		ExpectedNode *detection.Node
		ExpectedErr  error
	}
	var tests = map[string]test{}
	for testname, tt := range testsNode {
		tests[testname] = test{
			Input:        tt.String,
			ExpectedNode: tt.Node,
			ExpectedErr:  nil,
		}
	}

	// Actual tests
	for testname, tt := range tests {
		t.Run(testname, func(t *testing.T) {
			assert := assert.New(t)

			node, err := detection.ParseNode(tt.Input)

			assert.Equal(tt.ExpectedNode, node)
			assert.Equal(tt.ExpectedErr, err)
		})
	}
}

func TestParseMatcher(t *testing.T) {
	t.Parallel()

	// Prepare specific and common tests
	type test struct {
		Input           string
		ExpectedMatcher *detection.Matcher
		ExpectedErr     error
	}
	var tests = map[string]test{}
	for testname, tt := range testsMatcher {
		tests[testname] = test{
			Input:           tt.String,
			ExpectedMatcher: tt.Matcher,
			ExpectedErr:     nil,
		}
	}

	// Actual tests
	for testname, tt := range tests {
		t.Run(testname, func(t *testing.T) {
			assert := assert.New(t)

			matcher, err := detection.ParseMatcher(tt.Input)

			assert.Equal(tt.ExpectedMatcher, matcher)
			assert.Equal(tt.ExpectedErr, err)
		})
	}
}
