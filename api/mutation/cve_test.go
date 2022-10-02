package mutation_test

import (
	"testing"

	"github.com/pandatix/cvedetect/api/mutation"
	"github.com/pandatix/cvedetect/db"
	"github.com/pandatix/cvedetect/model"
	"github.com/stretchr/testify/assert"
)

func TestAddCVE(t *testing.T) {
	t.Parallel()

	var tests = map[string]struct {
		Memory      *db.Memory
		Input       db.AddCVEInput
		ExpectedCVE *model.CVE
		ExpectedErr error
	}{
		"no-match": {
			Memory: &db.Memory{
				Assets:       map[string]*model.Asset{},
				AssetVPIndex: map[string]map[string]struct{}{},
				CVEs:         map[string]*model.CVE{},
				CVEVPIndex:   map[string]map[string]struct{}{},
			},
			Input: db.AddCVEInput{
				ID:              "CVE-2021-28378",
				Description:     "Gitea 1.12.x and 1.13.x before 1.13.4 allows XSS via certain issue data in some situations.",
				PublicationDate: timeParse("2020-02-01T14:00Z"),
				LastUpdate:      timeParse("2020-02-01T14:00Z"),
				CVSS20Vector:    nil,
				CVSS30Vector:    nil,
				CVSS31Vector:    nil,
				Configurations: []db.AddCVENodeInput{
					{
						Negate:   nil,
						Operator: "OR",
						Children: []db.AddCVENodeInput{},
						CPEMatches: []db.AddCVENodeCPEMatchInput{
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
				References: []db.AddCVEReferenceInput{},
			},
			ExpectedCVE: &model.CVE{
				ID:              "CVE-2021-28378",
				Description:     "Gitea 1.12.x and 1.13.x before 1.13.4 allows XSS via certain issue data in some situations.",
				PublicationDate: timeParse("2020-02-01T14:00Z"),
				LastUpdate:      timeParse("2020-02-01T14:00Z"),
				CVSS20Vector:    nil,
				CVSS30Vector:    nil,
				CVSS31Vector:    nil,
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
				References: []*model.Reference{},
				Assets:     []*model.Asset{},
			},
			ExpectedErr: nil,
		},
		"MDC1-match": {
			Memory: &db.Memory{
				Assets: map[string]*model.Asset{
					"asset-1": {
						ID:       "asset-1",
						Name:     "Asset 1",
						CPE23:    "cpe:2.3:a:gitea:gitea:1.12.6:*:*:*:*:*:*:*",
						Parent:   nil,
						Children: []*model.Asset{},
						CVEs:     []*model.CVE{},
					},
					"asset-2": {
						ID:       "asset-2",
						Name:     "Asset 2",
						CPE23:    "cpe:2.3:a:gitea:gitea:1.15.0:*:*:*:*:*:*:*",
						Parent:   nil,
						Children: []*model.Asset{},
						CVEs:     []*model.CVE{},
					},
				},
				AssetVPIndex: map[string]map[string]struct{}{
					"gitea:gitea": {
						"asset-1": {},
						"asset-2": {},
					},
				},
				CVEs:       map[string]*model.CVE{},
				CVEVPIndex: map[string]map[string]struct{}{},
			},
			Input: db.AddCVEInput{
				ID:              "CVE-2021-28378",
				Description:     "Gitea 1.12.x and 1.13.x before 1.13.4 allows XSS via certain issue data in some situations.",
				PublicationDate: timeParse("2020-02-01T14:00Z"),
				LastUpdate:      timeParse("2020-02-01T14:00Z"),
				CVSS20Vector:    ptr("AV:N/AC:M/Au:S/C:N/I:P/A:N"),
				CVSS30Vector:    nil,
				CVSS31Vector:    ptr("CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N"),
				Configurations: []db.AddCVENodeInput{
					{
						Negate:   nil,
						Operator: "OR",
						Children: []db.AddCVENodeInput{},
						CPEMatches: []db.AddCVENodeCPEMatchInput{
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
				References: []db.AddCVEReferenceInput{},
			},
			ExpectedCVE: &model.CVE{
				ID:              "CVE-2021-28378",
				Description:     "Gitea 1.12.x and 1.13.x before 1.13.4 allows XSS via certain issue data in some situations.",
				PublicationDate: timeParse("2020-02-01T14:00Z"),
				LastUpdate:      timeParse("2020-02-01T14:00Z"),
				CVSS20Vector:    ptr("AV:N/AC:M/Au:S/C:N/I:P/A:N"),
				CVSS30Vector:    nil,
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
				References: []*model.Reference{},
				Assets: []*model.Asset{
					{
						ID: "asset-1",
					},
				},
			},
			ExpectedErr: nil,
		},
	}

	for testname, tt := range tests {
		t.Run(testname, func(t *testing.T) {
			assert := assert.New(t)

			cve, err := mutation.AddCVE(tt.Memory, tt.Input)

			assert.Equal(tt.ExpectedCVE, cve)
			assert.Equal(tt.ExpectedErr, err)
		})
	}
}

func TestUpdateCVE(t *testing.T) {
	t.Parallel()

	var tests = map[string]struct {
		Memory      *db.Memory
		Input       db.UpdateCVEInput
		ExpectedCVE *model.CVE
		ExpectedErr error
	}{
		"no-remaining-matches": {
			Memory: &db.Memory{
				Assets: map[string]*model.Asset{
					"asset": {
						ID:       "asset",
						Name:     "Asset",
						CPE23:    "cpe:2.3:a:gitea:gitea:1.12.6:*:*:*:*:*:*:*",
						Parent:   nil,
						Children: []*model.Asset{},
						CVEs: []*model.CVE{
							{
								ID: "CVE-2021-28378",
							},
						},
					},
				},
				AssetVPIndex: map[string]map[string]struct{}{
					"gitea:gitea": {
						"asset": {},
					},
				},
				CVEs: map[string]*model.CVE{
					"CVE-2021-28378": {
						ID:              "CVE-2021-28378",
						Description:     "Gitea 1.12.x and 1.13.x before 1.13.4 allows XSS via certain issue data in some situations.",
						PublicationDate: timeParse("2020-02-01T14:00Z"),
						LastUpdate:      timeParse("2020-02-01T14:00Z"),
						CVSS20Vector:    ptr("AV:N/AC:M/Au:S/C:N/I:P/A:N"),
						CVSS30Vector:    nil,
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
						References: []*model.Reference{},
						Assets: []*model.Asset{
							{
								ID: "asset",
							},
						},
					},
				},
				CVEVPIndex: map[string]map[string]struct{}{
					"gitea:gitea": {
						"CVE-2021-28378": {},
					},
				},
			},
			Input: db.UpdateCVEInput{
				ID:             "CVE-2021-28378",
				Configurations: []db.UpdateCVENodeInput{},
			},
			ExpectedCVE: &model.CVE{
				ID:              "CVE-2021-28378",
				Description:     "Gitea 1.12.x and 1.13.x before 1.13.4 allows XSS via certain issue data in some situations.",
				PublicationDate: timeParse("2020-02-01T14:00Z"),
				LastUpdate:      timeParse("2020-02-01T14:00Z"),
				CVSS20Vector:    ptr("AV:N/AC:M/Au:S/C:N/I:P/A:N"),
				CVSS30Vector:    nil,
				CVSS31Vector:    ptr("CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N"),
				Configurations:  []*model.Node{},
				References:      []*model.Reference{},
				Assets:          []*model.Asset{},
			},
			ExpectedErr: nil,
		},
		"new-matches": {
			Memory: &db.Memory{
				Assets: map[string]*model.Asset{
					"asset": {
						ID:       "asset",
						Name:     "Asset",
						CPE23:    "cpe:2.3:a:fake:asset:1.2.3:*:*:*:*:*:*:*",
						Parent:   nil,
						Children: []*model.Asset{},
						CVEs:     []*model.CVE{},
					},
				},
				AssetVPIndex: map[string]map[string]struct{}{
					"fake:asset": {
						"asset": {},
					},
				},
				CVEs: map[string]*model.CVE{
					"cve": {
						ID:              "cve",
						Description:     "CVE description",
						PublicationDate: timeParse("2022-01-02T14:30Z"),
						LastUpdate:      timeParse("2020-01-02T14:30Z"),
						CVSS20Vector:    nil,
						CVSS30Vector:    nil,
						CVSS31Vector:    nil,
						Configurations: []*model.Node{
							{
								Negate:   nil,
								Operator: "OR",
								Children: []*model.Node{},
								CPEMatches: []*model.CPEMatch{
									{
										Vulnerable:            true,
										CPE23:                 "cpe:2.3:a:other:asset:*:*:*:*:*:*:*:*",
										VersionStartIncluding: nil,
										VersionStartExcluding: nil,
										VersionEndIncluding:   nil,
										VersionEndExcluding:   nil,
									},
								},
							},
						},
						Assets:     []*model.Asset{},
						References: []*model.Reference{},
					},
				},
				CVEVPIndex: map[string]map[string]struct{}{
					"other:asset": {
						"cve": {},
					},
				},
			},
			Input: db.UpdateCVEInput{
				ID: "cve",
				Configurations: []db.UpdateCVENodeInput{
					{
						Negate:   nil,
						Operator: "OR",
						Children: nil,
						CPEMatches: []db.UpdateCVENodeCPEMatchInput{
							{
								Vulnerable:            true,
								CPE23:                 "cpe:2.3:a:fake:asset:*:*:*:*:*:*:*:*",
								VersionStartIncluding: nil,
								VersionStartExcluding: nil,
								VersionEndIncluding:   nil,
								VersionEndExcluding:   nil,
							},
						},
					},
				},
			},
			ExpectedCVE: &model.CVE{
				ID:              "cve",
				Description:     "CVE description",
				PublicationDate: timeParse("2022-01-02T14:30Z"),
				LastUpdate:      timeParse("2020-01-02T14:30Z"),
				CVSS20Vector:    nil,
				CVSS30Vector:    nil,
				CVSS31Vector:    nil,
				Configurations: []*model.Node{
					{
						Negate:   nil,
						Operator: "OR",
						Children: []*model.Node{},
						CPEMatches: []*model.CPEMatch{
							{
								Vulnerable:            true,
								CPE23:                 "cpe:2.3:a:fake:asset:*:*:*:*:*:*:*:*",
								VersionStartIncluding: nil,
								VersionStartExcluding: nil,
								VersionEndIncluding:   nil,
								VersionEndExcluding:   nil,
							},
						},
					},
				},
				Assets: []*model.Asset{
					{
						ID: "asset",
					},
				},
				References: []*model.Reference{},
			},
			ExpectedErr: nil,
		},
		"updated-matches": {
			Memory: &db.Memory{
				Assets: map[string]*model.Asset{
					"asset": {
						ID:       "asset",
						Name:     "Asset",
						CPE23:    "cpe:2.3:a:fake:asset:1.2.3:*:*:*:*:*:*:*",
						Parent:   nil,
						Children: []*model.Asset{},
						CVEs: []*model.CVE{
							{
								ID: "cve",
							},
						},
					},
				},
				AssetVPIndex: map[string]map[string]struct{}{
					"fake:asset": {
						"asset": {},
					},
				},
				CVEs: map[string]*model.CVE{
					"cve": {
						ID:              "cve",
						Description:     "CVE description",
						PublicationDate: timeParse("2022-01-02T14:30Z"),
						LastUpdate:      timeParse("2020-01-02T14:30Z"),
						CVSS20Vector:    nil,
						CVSS30Vector:    nil,
						CVSS31Vector:    nil,
						Configurations: []*model.Node{
							{
								Negate:   nil,
								Operator: "OR",
								Children: []*model.Node{},
								CPEMatches: []*model.CPEMatch{
									{
										Vulnerable:            true,
										CPE23:                 "cpe:2.3:a:fake:asset:1.2.3:*:*:*:*:*:*:*",
										VersionStartIncluding: nil,
										VersionStartExcluding: nil,
										VersionEndIncluding:   nil,
										VersionEndExcluding:   nil,
									},
								},
							},
						},
						Assets: []*model.Asset{
							{
								ID: "asset",
							},
						},
						References: []*model.Reference{},
					},
				},
				CVEVPIndex: map[string]map[string]struct{}{
					"fake:asset": {
						"cve": {},
					},
				},
			},
			Input: db.UpdateCVEInput{
				ID: "cve",
				Configurations: []db.UpdateCVENodeInput{
					{
						Negate:   nil,
						Operator: "OR",
						Children: []db.UpdateCVENodeInput{},
						CPEMatches: []db.UpdateCVENodeCPEMatchInput{
							{
								Vulnerable:            true,
								CPE23:                 "cpe:2.3:a:fake:asset:*:*:*:*:*:*:*:*",
								VersionStartIncluding: nil,
								VersionStartExcluding: nil,
								VersionEndIncluding:   nil,
								VersionEndExcluding:   ptr("2.0.0"),
							},
						},
					},
				},
			},
			ExpectedCVE: &model.CVE{
				ID:              "cve",
				Description:     "CVE description",
				PublicationDate: timeParse("2022-01-02T14:30Z"),
				LastUpdate:      timeParse("2020-01-02T14:30Z"),
				CVSS20Vector:    nil,
				CVSS30Vector:    nil,
				CVSS31Vector:    nil,
				Configurations: []*model.Node{
					{
						Negate:   nil,
						Operator: "OR",
						Children: []*model.Node{},
						CPEMatches: []*model.CPEMatch{
							{
								Vulnerable:            true,
								CPE23:                 "cpe:2.3:a:fake:asset:*:*:*:*:*:*:*:*",
								VersionStartIncluding: nil,
								VersionStartExcluding: nil,
								VersionEndIncluding:   nil,
								VersionEndExcluding:   ptr("2.0.0"),
							},
						},
					},
				},
				Assets: []*model.Asset{
					{
						ID: "asset",
					},
				},
				References: []*model.Reference{},
			},
			ExpectedErr: nil,
		},
	}

	for testname, tt := range tests {
		t.Run(testname, func(t *testing.T) {
			assert := assert.New(t)

			cve, err := mutation.UpdateCVE(tt.Memory, tt.Input)

			assert.Equal(tt.ExpectedCVE, cve)
			assert.Equal(tt.ExpectedErr, err)
		})
	}
}

func TestDeleteCVE(t *testing.T) {
	t.Parallel()

	var tests = map[string]struct {
		Memory      *db.Memory
		Input       db.DeleteCVEInput
		ExpectedCVE *model.CVE
		ExpectedErr error
	}{
		"drop-cve": {
			Memory: &db.Memory{
				Assets: map[string]*model.Asset{
					"asset": {
						ID:       "asset",
						Name:     "Asset",
						CPE23:    "cpe:2.3:a:fake:asset:1.2.3:*:*:*:*:*:*:*",
						Parent:   nil,
						Children: []*model.Asset{},
						CVEs: []*model.CVE{
							{
								ID: "cve",
							},
						},
					},
				},
				AssetVPIndex: map[string]map[string]struct{}{
					"fake:asset": {
						"asset": {},
					},
				},
				CVEs: map[string]*model.CVE{
					"cve": {
						ID:              "cve",
						Description:     "CVE description",
						PublicationDate: timeParse("2022-01-02T14:30Z"),
						LastUpdate:      timeParse("2020-01-02T14:30Z"),
						CVSS20Vector:    nil,
						CVSS30Vector:    nil,
						CVSS31Vector:    nil,
						Configurations: []*model.Node{
							{
								Negate:   nil,
								Operator: "OR",
								Children: []*model.Node{},
								CPEMatches: []*model.CPEMatch{
									{
										Vulnerable:            true,
										CPE23:                 "cpe:2.3:a:fake:asset:1.2.3:*:*:*:*:*:*:*",
										VersionStartIncluding: nil,
										VersionStartExcluding: nil,
										VersionEndIncluding:   nil,
										VersionEndExcluding:   nil,
									},
								},
							},
						},
						Assets: []*model.Asset{
							{
								ID: "asset",
							},
						},
						References: []*model.Reference{},
					},
				},
				CVEVPIndex: map[string]map[string]struct{}{
					"fake:asset": {
						"cve": {},
					},
				},
			},
			Input: db.DeleteCVEInput{
				ID: "cve",
			},
			ExpectedCVE: &model.CVE{
				ID:              "cve",
				Description:     "CVE description",
				PublicationDate: timeParse("2022-01-02T14:30Z"),
				LastUpdate:      timeParse("2020-01-02T14:30Z"),
				CVSS20Vector:    nil,
				CVSS30Vector:    nil,
				CVSS31Vector:    nil,
				Configurations: []*model.Node{
					{
						Negate:   nil,
						Operator: "OR",
						Children: []*model.Node{},
						CPEMatches: []*model.CPEMatch{
							{
								Vulnerable:            true,
								CPE23:                 "cpe:2.3:a:fake:asset:1.2.3:*:*:*:*:*:*:*",
								VersionStartIncluding: nil,
								VersionStartExcluding: nil,
								VersionEndIncluding:   nil,
								VersionEndExcluding:   nil,
							},
						},
					},
				},
				Assets: []*model.Asset{
					{
						ID: "asset",
					},
				},
				References: []*model.Reference{},
			},
		},
	}

	for testname, tt := range tests {
		t.Run(testname, func(t *testing.T) {
			assert := assert.New(t)

			cve, err := mutation.DeleteCVE(tt.Memory, tt.Input)

			assert.Equal(tt.ExpectedCVE, cve)
			assert.Equal(tt.ExpectedErr, err)
		})
	}
}
