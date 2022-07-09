package detection_test

import (
	"testing"
	"time"

	"github.com/pandatix/cvedetect/detection"
	"github.com/pandatix/cvedetect/model"
	"github.com/stretchr/testify/assert"
)

var cve_2021_28378 = &model.CVE{
	ID:              "CVE-2021-28378",
	Description:     "Gitea 1.12.x and 1.13.x before 1.13.4 allows XSS via certain issue data in some situations.",
	PublicationDate: timeParse("2021-03-15T06:15Z"),
	LastUpdate:      timeParse("2021-12-16T18:20Z"),
	CVSS20Vector:    ptr("AV:N/AC:M/Au:S/C:N/I:P/A:N"),
	CVSS31Vector:    ptr("CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N"),
	Configurations: []*model.Node{
		{
			Negate:   nil,
			Operator: "OR",
			Children: []*model.Node{},
			CPEMatches: []*model.CPEMatch{
				{
					Vulnerable:            true,
					CPE23:                 "cpe:2.3:a:gitea:gitea:*:*:*:*:*:*:*:*",
					VersionStartIncluding: ptr("1.12.0"),
					VersionStartExcluding: nil,
					VersionEndIncluding:   ptr("1.12.6"),
					VersionEndExcluding:   nil,
				}, {
					Vulnerable:            true,
					CPE23:                 "cpe:2.3:a:gitea:gitea:*:*:*:*:*:*:*:*",
					VersionStartIncluding: ptr("1.13.0"),
					VersionStartExcluding: nil,
					VersionEndIncluding:   nil,
					VersionEndExcluding:   ptr("1.13.4"),
				},
			},
		},
	},
	Components: []*model.Component{},
}

var cve_2022_1058 = &model.CVE{
	ID:              "CVE-2022-1058",
	Description:     "Open Redirect on login in GitHub repository go-gitea/gitea prior to 1.16.5.",
	PublicationDate: timeParse("2022-03-24T15:15Z"),
	LastUpdate:      timeParse("2022-03-29T15:40Z"),
	CVSS20Vector:    ptr("AV:N/AC:M/Au:N/C:P/I:P/A:N"),
	CVSS31Vector:    ptr("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),
	Configurations: []*model.Node{
		{
			Negate:   nil,
			Operator: "OR",
			Children: []*model.Node{},
			CPEMatches: []*model.CPEMatch{
				{
					Vulnerable:            true,
					CPE23:                 "cpe:2.3:a:gitea:gitea:*:*:*:*:*:*:*:*",
					VersionStartIncluding: nil,
					VersionStartExcluding: nil,
					VersionEndIncluding:   nil,
					VersionEndExcluding:   ptr("1.16.5"),
				},
			},
		},
	},
	Components: []*model.Component{},
}

func TestMDC1(t *testing.T) {
	t.Parallel()

	var tests = map[string]struct {
		Component    *model.Component
		CVE          *model.CVE
		ExpectedVuln bool
	}{
		"CVE-2021-28378-matching": {
			Component: &model.Component{
				ID:       "comp",
				Name:     "Gitea",
				CPE23:    "cpe:2.3:a:gitea:gitea:1.12.6:*:*:*:*:*:*:*",
				Parent:   nil,
				Children: []*model.Component{},
				CVEs:     []*model.CVE{},
			},
			CVE:          cve_2021_28378,
			ExpectedVuln: true,
		},
		"CVE-2021-28378-not-matching": {
			Component: &model.Component{
				ID:       "comp",
				Name:     "Gitea",
				CPE23:    "cpe:2.3:a:gitea:gitea:1.13.4:*:*:*:*:*:*:*",
				Parent:   nil,
				Children: []*model.Component{},
				CVEs:     []*model.CVE{},
			},
			CVE:          cve_2021_28378,
			ExpectedVuln: false,
		},
		"CVE-2022-1058": {
			Component: &model.Component{
				ID:       "comp",
				Name:     "Gitea",
				CPE23:    "cpe:2.3:a:gitea:gitea:1.15.4:*:*:*:*:*:*:*",
				Parent:   nil,
				Children: []*model.Component{},
				CVEs:     []*model.CVE{},
			},
			CVE:          cve_2022_1058,
			ExpectedVuln: true,
		},
		"Log4Shell-extract": {
			// This should return true under MDCN, but can't be detected
			// using MDC=1.
			Component: &model.Component{
				ID:       "comp",
				Name:     "Siemens SSPA-T3000 SES3000",
				CPE23:    "cpe:2.3:o:siemens:sppa-t3000_ses3000_firmware:*:*:*:*:*:*:*:*",
				Parent:   nil,
				Children: []*model.Component{},
				CVEs:     []*model.CVE{},
			},
			CVE: &model.CVE{
				ID:              "CVE-2021-44228",
				Description:     "Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases 2.12.2, 2.12.3, and 2.3.1) JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled. From log4j 2.15.0, this behavior has been disabled by default. From version 2.16.0 (along with 2.12.2, 2.12.3, and 2.3.1), this functionality has been completely removed. Note that this vulnerability is specific to log4j-core and does not affect log4net, log4cxx, or other Apache Logging Services projects.",
				PublicationDate: timeParse("2021-12-10T10:15Z"),
				LastUpdate:      timeParse("2022-05-05T23:15Z"),
				CVSS20Vector:    ptr("AV:N/AC:M/Au:N/C:C/I:C/A:C"),
				CVSS31Vector:    ptr("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"),
				Configurations: []*model.Node{
					{
						Negate:   nil,
						Operator: "AND",
						Children: []*model.Node{
							{
								Negate:   nil,
								Operator: "OR",
								Children: []*model.Node{},
								CPEMatches: []*model.CPEMatch{
									{
										Vulnerable:            true,
										CPE23:                 "cpe:2.3:o:siemens:sppa-t3000_ses3000_firmware:*:*:*:*:*:*:*:*",
										VersionStartIncluding: nil,
										VersionStartExcluding: nil,
										VersionEndIncluding:   nil,
										VersionEndExcluding:   nil,
									},
								},
							}, {
								Negate:   nil,
								Operator: "OR",
								Children: []*model.Node{},
								CPEMatches: []*model.CPEMatch{
									{
										Vulnerable:            false,
										CPE23:                 "cpe:2.3:h:siemens:sppa-t3000_ses3000:-:*:*:*:*:*:*:*",
										VersionStartIncluding: nil,
										VersionStartExcluding: nil,
										VersionEndIncluding:   nil,
										VersionEndExcluding:   nil,
									},
								},
							},
						},
						CPEMatches: []*model.CPEMatch{},
					},
				},
				Components: []*model.Component{},
			},
			ExpectedVuln: false,
		},
	}

	for testname, tt := range tests {
		t.Run(testname, func(t *testing.T) {
			assert := assert.New(t)

			vuln := detection.MDC1(tt.Component, tt.CVE)

			assert.Equal(tt.ExpectedVuln, vuln)
		})
	}
}

func timeParse(ts string) time.Time {
	t, err := time.Parse("2006-01-02T15:04Z", ts)
	if err != nil {
		panic(err)
	}
	return t
}
