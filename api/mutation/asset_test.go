package mutation_test

import (
	"testing"

	"github.com/pandatix/cvedetect/api/mutation"
	"github.com/pandatix/cvedetect/db"
	"github.com/pandatix/cvedetect/model"
	"github.com/stretchr/testify/assert"
)

func TestAddAsset(t *testing.T) {
	t.Parallel()

	var tests = map[string]struct {
		Memory        *db.Memory
		Input         db.AddAssetInput
		ExpectedAsset *model.Asset
		ExpectedErr   error
	}{
		"no-match": {
			Memory: &db.Memory{
				Assets:       map[string]*model.Asset{},
				AssetVPIndex: map[string]map[string]struct{}{},
				CVEs:         map[string]*model.CVE{},
				CVEVPIndex:   map[string]map[string]struct{}{},
			},
			Input: db.AddAssetInput{
				ID:       "asset",
				Name:     "Asset",
				CPE23:    "cpe:2.3:a:fake:asset:*:*:*:*:*:*:*:*",
				Parents:  []db.AddAssetParentInput{},
				Children: []db.AddAssetChildInput{},
			},
			ExpectedAsset: &model.Asset{
				ID:       "asset",
				Name:     "Asset",
				CPE23:    "cpe:2.3:a:fake:asset:*:*:*:*:*:*:*:*",
				Parents:  []*model.Asset{},
				Children: []*model.Asset{},
				CVEs:     []*model.CVE{},
			},
			ExpectedErr: nil,
		},
		"MDC1-match": {
			Memory: &db.Memory{
				Assets:       map[string]*model.Asset{},
				AssetVPIndex: map[string]map[string]struct{}{},
				CVEs: map[string]*model.CVE{
					"cve": {
						ID:              "cve",
						Description:     "CVE description",
						PublicationDate: timeParse("2022-02-01T14:30Z"),
						LastUpdate:      timeParse("2022-02-01T14:30Z"),
						CVSS2Vector:     nil,
						CVSS3Vector:     nil,
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
						Assets:     []*model.Asset{},
						References: []*model.Reference{},
					},
				},
				CVEVPIndex: map[string]map[string]struct{}{
					"fake:asset": {
						"cve": {},
					},
				},
			},
			Input: db.AddAssetInput{
				ID:       "asset",
				Name:     "Asset",
				CPE23:    "cpe:2.3:a:fake:asset:*:*:*:*:*:*:*:*",
				Parents:  []db.AddAssetParentInput{},
				Children: []db.AddAssetChildInput{},
			},
			ExpectedAsset: &model.Asset{
				ID:       "asset",
				Name:     "Asset",
				CPE23:    "cpe:2.3:a:fake:asset:*:*:*:*:*:*:*:*",
				Parents:  []*model.Asset{},
				Children: []*model.Asset{},
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

			asset, err := mutation.AddAsset(tt.Memory, tt.Input)

			assert.Equal(tt.ExpectedAsset, asset)
			assert.Equal(tt.ExpectedErr, err)
		})
	}
}

func TestUpdateAsset(t *testing.T) {
	t.Parallel()

	var tests = map[string]struct {
		Memory        *db.Memory
		Input         db.UpdateAssetInput
		ExpectedAsset *model.Asset
		ExpectedErr   error
	}{
		"no-remaining-matches": {
			Memory: &db.Memory{
				Assets: map[string]*model.Asset{
					"asset": {
						ID:       "asset",
						Name:     "Asset",
						CPE23:    "cpe:2.3:a:fake:asset:*:*:*:*:*:*:*:*",
						Parents:  []*model.Asset{},
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
						LastUpdate:      timeParse("2022-01-02T14:30Z"),
						CVSS2Vector:     nil,
						CVSS3Vector:     nil,
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
				},
				CVEVPIndex: map[string]map[string]struct{}{
					"fake:asset": {
						"cve": {},
					},
				},
			},
			Input: db.UpdateAssetInput{
				ID:       "asset",
				Name:     nil,
				CPE23:    ptr("cpe:2.3:a:other:asset:*:*:*:*:*:*:*:*"),
				Parents:  nil,
				Children: nil,
				CVEs:     nil,
			},
			ExpectedAsset: &model.Asset{
				ID:       "asset",
				Name:     "Asset",
				CPE23:    "cpe:2.3:a:other:asset:*:*:*:*:*:*:*:*",
				Parents:  []*model.Asset{},
				Children: []*model.Asset{},
				CVEs:     []*model.CVE{},
			},
			ExpectedErr: nil,
		},
		"new-matches": {
			Memory: &db.Memory{
				Assets: map[string]*model.Asset{
					"asset": {
						ID:       "asset",
						Name:     "Asset",
						CPE23:    "cpe:2.3:a:other:asset:*:*:*:*:*:*:*:*",
						Parents:  []*model.Asset{},
						Children: []*model.Asset{},
						CVEs:     []*model.CVE{},
					},
				},
				AssetVPIndex: map[string]map[string]struct{}{
					"other:asset": {
						"asset": {},
					},
				},
				CVEs: map[string]*model.CVE{
					"cve": {
						ID:              "cve",
						Description:     "CVE description",
						PublicationDate: timeParse("2022-01-02T14:30Z"),
						LastUpdate:      timeParse("2022-01-02T14:30Z"),
						CVSS2Vector:     nil,
						CVSS3Vector:     nil,
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
						Assets:     []*model.Asset{},
						References: []*model.Reference{},
					},
				},
				CVEVPIndex: map[string]map[string]struct{}{
					"fake:asset": {
						"cve": {},
					},
				},
			},
			Input: db.UpdateAssetInput{
				ID:       "asset",
				Name:     nil,
				CPE23:    ptr("cpe:2.3:a:fake:asset:*:*:*:*:*:*:*:*"),
				Parents:  nil,
				Children: nil,
				CVEs:     nil,
			},
			ExpectedAsset: &model.Asset{
				ID:       "asset",
				Name:     "Asset",
				CPE23:    "cpe:2.3:a:fake:asset:*:*:*:*:*:*:*:*",
				Parents:  []*model.Asset{},
				Children: []*model.Asset{},
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
				Assets: map[string]*model.Asset{
					"asset": {
						ID:       "asset",
						Name:     "Asset",
						CPE23:    "cpe:2.3:a:fake:asset:*:*:*:*:*:*:*:*",
						Parents:  []*model.Asset{},
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
						LastUpdate:      timeParse("2022-01-02T14:30Z"),
						CVSS2Vector:     nil,
						CVSS3Vector:     nil,
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
				},
				CVEVPIndex: map[string]map[string]struct{}{
					"fake:asset": {
						"cve": {},
					},
				},
			},
			Input: db.UpdateAssetInput{
				ID:       "asset",
				Name:     nil,
				CPE23:    ptr("cpe:2.3:a:fake:asset:1.2.3:*:*:*:*:*:*:*"),
				Parents:  nil,
				Children: nil,
				CVEs:     nil,
			},
			ExpectedAsset: &model.Asset{
				ID:       "asset",
				Name:     "Asset",
				CPE23:    "cpe:2.3:a:fake:asset:1.2.3:*:*:*:*:*:*:*",
				Parents:  []*model.Asset{},
				Children: []*model.Asset{},
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

			asset, err := mutation.UpdateAsset(tt.Memory, tt.Input)

			assert.Equal(tt.ExpectedAsset, asset)
			assert.Equal(tt.ExpectedErr, err)
		})
	}
}

func TestDeleteAsset(t *testing.T) {
	t.Parallel()

	var tests = map[string]struct {
		Memory        *db.Memory
		Input         db.DeleteAssetInput
		ExpectedAsset *model.Asset
		ExpectedErr   error
	}{
		"drop-asset": {
			Memory: &db.Memory{
				Assets: map[string]*model.Asset{
					"asset": {
						ID:       "asset",
						Name:     "Asset",
						CPE23:    "cpe:2.3:a:fake:asset:*:*:*:*:*:*:*:*",
						Parents:  []*model.Asset{},
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
						LastUpdate:      timeParse("2022-01-02T14:30Z"),
						CVSS2Vector:     nil,
						CVSS3Vector:     nil,
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
				},
				CVEVPIndex: map[string]map[string]struct{}{
					"fake:asset": {
						"cve": {},
					},
				},
			},
			Input: db.DeleteAssetInput{
				ID: "asset",
			},
			ExpectedAsset: &model.Asset{
				ID:       "asset",
				Name:     "Asset",
				CPE23:    "cpe:2.3:a:fake:asset:*:*:*:*:*:*:*:*",
				Parents:  []*model.Asset{},
				Children: []*model.Asset{},
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

			asset, err := mutation.DeleteAsset(tt.Memory, tt.Input)

			assert.Equal(tt.ExpectedAsset, asset)
			assert.Equal(tt.ExpectedErr, err)
		})
	}
}
