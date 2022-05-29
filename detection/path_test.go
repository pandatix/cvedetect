package detection_test

import (
	"testing"

	"github.com/pandatix/cvedetect/detection"
	"github.com/stretchr/testify/assert"
)

func ptr[T any](t T) *T {
	return &t
}

func TestNodeString(t *testing.T) {
	t.Parallel()

	var tests = map[string]struct {
		Node           *detection.Node
		ExpectedString string
	}{
		"one-node-one-matcher": {
			Node: &detection.Node{
				Operator: "OR",
				Children: nil,
				Matchers: []*detection.Matcher{
					{
						SuperCPE23:            "cpe:2.3:a:fake:component:*:*:*:*:*:*:*:*",
						SubCPE23:              "cpe:2.3:a:fake:component:5:*:*:*:*:*:*:*",
						VersionStartIncluding: nil,
						VersionStartExcluding: nil,
						VersionEndIncluding:   nil,
						VersionEndExcluding:   nil,
					},
				},
			},
			ExpectedString: `(|(cpe:2.3:a:fake:component:*:*:*:*:*:*:*:* incl cpe:2.3:a:fake:component:5:*:*:*:*:*:*:* , ))`,
		},
		"one-node-one-matcher-version-interval": {
			Node: &detection.Node{
				Operator: "OR",
				Children: nil,
				Matchers: []*detection.Matcher{
					{
						SuperCPE23:            "cpe:2.3:a:fake:component:*:*:*:*:*:*:*:*",
						SubCPE23:              "cpe:2.3:a:fake:component:2:u2:*:*:*:*:*:*",
						VersionStartIncluding: nil,
						VersionStartExcluding: nil,
						VersionEndIncluding:   nil,
						VersionEndExcluding:   ptr("3.5.7"),
					},
				},
			},
			ExpectedString: `(|(cpe:2.3:a:fake:component:*:*:*:*:*:*:*:* incl cpe:2.3:a:fake:component:2:u2:*:*:*:*:*:* , 2 < 3.5.7))`,
		},
		"and-or-version-interval": {
			Node: &detection.Node{
				Operator: "AND",
				Children: []*detection.Node{
					{
						Operator: "OR",
						Children: nil,
						Matchers: []*detection.Matcher{
							{
								SuperCPE23:            "cpe:2.3:a:gitea:gitea:*:*:*:*:*:*:*:*",
								SubCPE23:              "cpe:2.3:a:gitea:gitea:1.12.6:*:*:*:*:docker:*:*",
								VersionStartIncluding: ptr("1.12.0"),
								VersionStartExcluding: nil,
								VersionEndIncluding:   ptr("1.12.6"),
								VersionEndExcluding:   nil,
							}, {
								SuperCPE23:            "cpe:2.3:a:gitea:gitea:*:*:*:*:*:*:*:*",
								SubCPE23:              "cpe:2.3:a:gitea:gitea:1.13.2:*:*:*:*:docker:*:*",
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
								SuperCPE23:            "cpe:2.3:a:gitea:gitea:*:*:*:*:docker:*:*",
								SubCPE23:              "cpe:2.3:a:gitea:gitea:1.12.6:*:*:*:*:*:*:*",
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
			ExpectedString: `(&(|(cpe:2.3:a:gitea:gitea:*:*:*:*:*:*:*:* incl cpe:2.3:a:gitea:gitea:1.12.6:*:*:*:*:*:docker:*:* , 1.12.0 <= 1.12.6 <= 1.12.6)(cpe:2.3:a:gitea:gitea:*:*:*:*:*:*:*:* incl cpe:2.3:a:gitea:gitea:1.12.6:*:*:*:*:docker:*:* , 1.13.0 <= 1.13.2 < 1.13.4))(|(cpe:2.3:a:gitea:gitea:*:*:*:*:docker:*:* incl cpe:2.3:a:gitea:gitea:1.12.6:*:*:*:*:*:*:* , )))`,
		},
	}

	for testname, tt := range tests {
		t.Run(testname, func(t *testing.T) {
			assert := assert.New(t)

			str := tt.Node.String()

			assert.Equal(tt.ExpectedString, str)
		})
	}
}
