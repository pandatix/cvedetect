package mutation_test

import (
	"testing"

	"github.com/pandatix/cvedetect/api/mutation"
	"github.com/pandatix/cvedetect/db"
	"github.com/pandatix/cvedetect/model"
	"github.com/stretchr/testify/assert"
)

func TestAddComponent(t *testing.T) {
	t.Parallel()

	var tests = map[string]struct {
		Memory            *db.Memory
		Input             db.AddComponentInput
		ExpectedComponent *model.Component
		ExpectedErr       error
	}{
		"no-match": {
			Memory: &db.Memory{
				Components:  map[string]*model.Component{},
				CompVPIndex: map[string]map[string]struct{}{},
				CVEs:        map[string]*model.CVE{},
				CVEVPIndex:  map[string]map[string]struct{}{},
			},
			Input: db.AddComponentInput{
				ID:       "comp",
				Name:     "Component",
				CPE23:    "cpe:2.3:a:fake:component:*:*:*:*:*:*:*:*",
				Parent:   nil,
				Children: []db.AddComponentChildInput{},
			},
			ExpectedComponent: &model.Component{
				ID:       "comp",
				Name:     "Component",
				CPE23:    "cpe:2.3:a:fake:component:*:*:*:*:*:*:*:*",
				Parent:   nil,
				Children: []*model.Component{},
				CVEs:     []*model.CVE{},
			},
			ExpectedErr: nil,
		},
		"MDC1-match": {
			Memory: &db.Memory{
				Components:  map[string]*model.Component{},
				CompVPIndex: map[string]map[string]struct{}{},
				CVEs: map[string]*model.CVE{
					"cve": {
						ID:              "cve",
						Description:     "CVE description",
						PublicationDate: timeParse("2022-02-01T14:30Z"),
						LastUpdate:      timeParse("2022-02-01T14:30Z"),
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
										CPE23:                 "cpe:2.3:a:fake:component:*:*:*:*:*:*:*:*",
										VersionStartIncluding: nil,
										VersionStartExcluding: nil,
										VersionEndIncluding:   nil,
										VersionEndExcluding:   nil,
									},
								},
							},
						},
						Components: []*model.Component{},
						References: []*model.Reference{},
					},
				},
				CVEVPIndex: map[string]map[string]struct{}{
					"fake:component": {
						"cve": {},
					},
				},
			},
			Input: db.AddComponentInput{
				ID:       "comp",
				Name:     "Component",
				CPE23:    "cpe:2.3:a:fake:component:*:*:*:*:*:*:*:*",
				Parent:   nil,
				Children: []db.AddComponentChildInput{},
			},
			ExpectedComponent: &model.Component{
				ID:       "comp",
				Name:     "Component",
				CPE23:    "cpe:2.3:a:fake:component:*:*:*:*:*:*:*:*",
				Parent:   nil,
				Children: []*model.Component{},
				CVEs: []*model.CVE{
					{
						ID: "cve",
					},
				},
			},
		},
	}

	for testname, tt := range tests {
		t.Run(testname, func(t *testing.T) {
			assert := assert.New(t)

			comp, err := mutation.AddComponent(tt.Memory, tt.Input)

			assert.Equal(tt.ExpectedComponent, comp)
			assert.Equal(tt.ExpectedErr, err)
		})
	}
}

func TestUpdateComponent(t *testing.T) {
	t.Parallel()

	var tests = map[string]struct {
		Memory            *db.Memory
		Input             db.UpdateComponentInput
		ExpectedComponent *model.Component
		ExpectedErr       error
	}{
		"no-remaining-matches": {
			Memory: &db.Memory{
				Components: map[string]*model.Component{
					"comp": {
						ID:       "comp",
						Name:     "Component",
						CPE23:    "cpe:2.3:a:fake:component:*:*:*:*:*:*:*:*",
						Parent:   nil,
						Children: []*model.Component{},
						CVEs: []*model.CVE{
							{
								ID: "cve",
							},
						},
					},
				},
				CompVPIndex: map[string]map[string]struct{}{
					"fake:component": {
						"comp": {},
					},
				},
				CVEs: map[string]*model.CVE{
					"cve": {
						ID:              "cve",
						Description:     "CVE description",
						PublicationDate: timeParse("2022-01-02T14:30Z"),
						LastUpdate:      timeParse("2022-01-02T14:30Z"),
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
										CPE23:                 "cpe:2.3:a:fake:component:*:*:*:*:*:*:*:*",
										VersionStartIncluding: nil,
										VersionStartExcluding: nil,
										VersionEndIncluding:   nil,
										VersionEndExcluding:   nil,
									},
								},
							},
						},
						Components: []*model.Component{
							{
								ID: "comp",
							},
						},
						References: []*model.Reference{},
					},
				},
				CVEVPIndex: map[string]map[string]struct{}{
					"fake:component": {
						"cve": {},
					},
				},
			},
			Input: db.UpdateComponentInput{
				ID:       "comp",
				Name:     nil,
				CPE23:    ptr("cpe:2.3:a:other:component:*:*:*:*:*:*:*:*"),
				Parent:   nil,
				Children: nil,
				CVEs:     nil,
			},
			ExpectedComponent: &model.Component{
				ID:       "comp",
				Name:     "Component",
				CPE23:    "cpe:2.3:a:other:component:*:*:*:*:*:*:*:*",
				Parent:   nil,
				Children: []*model.Component{},
				CVEs:     []*model.CVE{},
			},
			ExpectedErr: nil,
		},
		"new-matches": {
			Memory: &db.Memory{
				Components: map[string]*model.Component{
					"comp": {
						ID:       "comp",
						Name:     "Component",
						CPE23:    "cpe:2.3:a:other:component:*:*:*:*:*:*:*:*",
						Parent:   nil,
						Children: []*model.Component{},
						CVEs:     []*model.CVE{},
					},
				},
				CompVPIndex: map[string]map[string]struct{}{
					"other:component": {
						"comp": {},
					},
				},
				CVEs: map[string]*model.CVE{
					"cve": {
						ID:              "cve",
						Description:     "CVE description",
						PublicationDate: timeParse("2022-01-02T14:30Z"),
						LastUpdate:      timeParse("2022-01-02T14:30Z"),
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
										CPE23:                 "cpe:2.3:a:fake:component:*:*:*:*:*:*:*:*",
										VersionStartIncluding: nil,
										VersionStartExcluding: nil,
										VersionEndIncluding:   nil,
										VersionEndExcluding:   nil,
									},
								},
							},
						},
						Components: []*model.Component{},
						References: []*model.Reference{},
					},
				},
				CVEVPIndex: map[string]map[string]struct{}{
					"fake:component": {
						"cve": {},
					},
				},
			},
			Input: db.UpdateComponentInput{
				ID:       "comp",
				Name:     nil,
				CPE23:    ptr("cpe:2.3:a:fake:component:*:*:*:*:*:*:*:*"),
				Parent:   nil,
				Children: nil,
				CVEs:     nil,
			},
			ExpectedComponent: &model.Component{
				ID:       "comp",
				Name:     "Component",
				CPE23:    "cpe:2.3:a:fake:component:*:*:*:*:*:*:*:*",
				Parent:   nil,
				Children: []*model.Component{},
				CVEs: []*model.CVE{
					{
						ID: "cve",
					},
				},
			},
			ExpectedErr: nil,
		},
		"updated-matches": {
			Memory: &db.Memory{
				Components: map[string]*model.Component{
					"comp": {
						ID:       "comp",
						Name:     "Component",
						CPE23:    "cpe:2.3:a:fake:component:*:*:*:*:*:*:*:*",
						Parent:   nil,
						Children: []*model.Component{},
						CVEs: []*model.CVE{
							{
								ID: "cve",
							},
						},
					},
				},
				CompVPIndex: map[string]map[string]struct{}{
					"fake:component": {
						"comp": {},
					},
				},
				CVEs: map[string]*model.CVE{
					"cve": {
						ID:              "cve",
						Description:     "CVE description",
						PublicationDate: timeParse("2022-01-02T14:30Z"),
						LastUpdate:      timeParse("2022-01-02T14:30Z"),
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
										CPE23:                 "cpe:2.3:a:fake:component:*:*:*:*:*:*:*:*",
										VersionStartIncluding: nil,
										VersionStartExcluding: nil,
										VersionEndIncluding:   nil,
										VersionEndExcluding:   nil,
									},
								},
							},
						},
						Components: []*model.Component{
							{
								ID: "comp",
							},
						},
						References: []*model.Reference{},
					},
				},
				CVEVPIndex: map[string]map[string]struct{}{
					"fake:component": {
						"cve": {},
					},
				},
			},
			Input: db.UpdateComponentInput{
				ID:       "comp",
				Name:     nil,
				CPE23:    ptr("cpe:2.3:a:fake:component:1.2.3:*:*:*:*:*:*:*"),
				Parent:   nil,
				Children: nil,
				CVEs:     nil,
			},
			ExpectedComponent: &model.Component{
				ID:       "comp",
				Name:     "Component",
				CPE23:    "cpe:2.3:a:fake:component:1.2.3:*:*:*:*:*:*:*",
				Parent:   nil,
				Children: []*model.Component{},
				CVEs: []*model.CVE{
					{
						ID: "cve",
					},
				},
			},
			ExpectedErr: nil,
		},
	}

	for testname, tt := range tests {
		t.Run(testname, func(t *testing.T) {
			assert := assert.New(t)

			comp, err := mutation.UpdateComponent(tt.Memory, tt.Input)

			assert.Equal(tt.ExpectedComponent, comp)
			assert.Equal(tt.ExpectedErr, err)
		})
	}
}

func TestDeleteComponent(t *testing.T) {
	t.Parallel()

	var tests = map[string]struct {
		Memory            *db.Memory
		Input             db.DeleteComponentInput
		ExpectedComponent *model.Component
		ExpectedErr       error
	}{
		"drop-component": {
			Memory: &db.Memory{
				Components: map[string]*model.Component{
					"comp": {
						ID:       "comp",
						Name:     "Component",
						CPE23:    "cpe:2.3:a:fake:component:*:*:*:*:*:*:*:*",
						Parent:   nil,
						Children: []*model.Component{},
						CVEs: []*model.CVE{
							{
								ID: "cve",
							},
						},
					},
				},
				CompVPIndex: map[string]map[string]struct{}{
					"fake:component": {
						"comp": {},
					},
				},
				CVEs: map[string]*model.CVE{
					"cve": {
						ID:              "cve",
						Description:     "CVE description",
						PublicationDate: timeParse("2022-01-02T14:30Z"),
						LastUpdate:      timeParse("2022-01-02T14:30Z"),
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
										CPE23:                 "cpe:2.3:a:fake:component:*:*:*:*:*:*:*:*",
										VersionStartIncluding: nil,
										VersionStartExcluding: nil,
										VersionEndIncluding:   nil,
										VersionEndExcluding:   nil,
									},
								},
							},
						},
						Components: []*model.Component{
							{
								ID: "comp",
							},
						},
						References: []*model.Reference{},
					},
				},
				CVEVPIndex: map[string]map[string]struct{}{
					"fake:component": {
						"cve": {},
					},
				},
			},
			Input: db.DeleteComponentInput{
				ID: "comp",
			},
			ExpectedComponent: &model.Component{
				ID:       "comp",
				Name:     "Component",
				CPE23:    "cpe:2.3:a:fake:component:*:*:*:*:*:*:*:*",
				Parent:   nil,
				Children: []*model.Component{},
				CVEs: []*model.CVE{
					{
						ID: "cve",
					},
				},
			},
		},
	}

	for testname, tt := range tests {
		t.Run(testname, func(t *testing.T) {
			assert := assert.New(t)

			comp, err := mutation.DeleteComponent(tt.Memory, tt.Input)

			assert.Equal(tt.ExpectedComponent, comp)
			assert.Equal(tt.ExpectedErr, err)
		})
	}
}
