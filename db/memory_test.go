package db

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/pandatix/cvedetect/model"
	"github.com/stretchr/testify/assert"
)

func unsem(mem *Memory) (dst any) {
	b, _ := json.Marshal(mem)
	_ = json.Unmarshal(b, &dst)
	return
}

func assertEqual(expected, actual *Memory, assert *assert.Assertions) {
	exp := unsem(expected)
	act := unsem(actual)

	assert.Equal(exp, act)
}

func ptr[T any](t T) *T {
	return &t
}

func timeParse(ts string) time.Time {
	t, err := time.Parse("2006-01-02T15:04Z", ts)
	if err != nil {
		panic(err)
	}
	return t
}

func TestMemoryGetAsset(t *testing.T) {
	t.Parallel()

	var tests = map[string]struct {
		Memory         *Memory
		Input          GetAssetInput
		ExpectedAsset  *model.Asset
		ExpectedErr    error
		ExpectedMemory *Memory
	}{
		"unexisting-asset": {
			Memory: &Memory{
				Assets:       map[string]*model.Asset{},
				CVEs:         map[string]*model.CVE{},
				AssetVPIndex: map[string]map[string]struct{}{},
				CVEVPIndex:   map[string]map[string]struct{}{},
			},
			Input: GetAssetInput{
				ID: "asset",
			},
			ExpectedAsset: nil,
			ExpectedErr: &ErrNotExist{
				K: KeyAsset,
				V: "asset",
			},
			ExpectedMemory: &Memory{
				Assets:       map[string]*model.Asset{},
				CVEs:         map[string]*model.CVE{},
				AssetVPIndex: map[string]map[string]struct{}{},
				CVEVPIndex:   map[string]map[string]struct{}{},
			},
		},
		"existing-asset": {
			Memory: &Memory{
				Assets: map[string]*model.Asset{
					"asset": {
						ID:           "asset",
						Name:         "Asset",
						CPE23:        "cpe:2.3:a:fake:asset:*:*:*:*:*:*:*:*",
						Dependents:   []*model.Asset{},
						Dependencies: []*model.Asset{},
						CVEs:         []*model.CVE{},
					},
				},
				CVEs: map[string]*model.CVE{},
				AssetVPIndex: map[string]map[string]struct{}{
					"fake:asset": {
						"asset": {},
					},
				},
				CVEVPIndex: map[string]map[string]struct{}{},
			},
			Input: GetAssetInput{
				ID: "asset",
			},
			ExpectedAsset: &model.Asset{
				ID:           "asset",
				Name:         "Asset",
				CPE23:        "cpe:2.3:a:fake:asset:*:*:*:*:*:*:*:*",
				Dependents:   []*model.Asset{},
				Dependencies: []*model.Asset{},
				CVEs:         []*model.CVE{},
			},
			ExpectedErr: nil,
			ExpectedMemory: &Memory{
				Assets: map[string]*model.Asset{
					"asset": {
						ID:           "asset",
						Name:         "Asset",
						CPE23:        "cpe:2.3:a:fake:asset:*:*:*:*:*:*:*:*",
						Dependents:   []*model.Asset{},
						Dependencies: []*model.Asset{},
						CVEs:         []*model.CVE{},
					},
				},
				AssetVPIndex: map[string]map[string]struct{}{
					"fake:asset": {
						"asset": {},
					},
				},
				CVEs:       map[string]*model.CVE{},
				CVEVPIndex: map[string]map[string]struct{}{},
			},
		},
	}

	for testname, tt := range tests {
		t.Run(testname, func(t *testing.T) {
			assert := assert.New(t)

			asset, err := tt.Memory.GetAsset(tt.Input)

			assert.Equal(tt.ExpectedAsset, asset)
			assert.Equal(tt.ExpectedErr, err)
			assertEqual(tt.ExpectedMemory, tt.Memory, assert)

			// Check modified input/output does not affect database
			alter(tt.Input)
			alter(asset)
			assertEqual(tt.ExpectedMemory, tt.Memory, assert)
		})
	}
}

func TestMemoryQueryAssets(t *testing.T) {
	t.Parallel()

	var tests = map[string]struct {
		Memory         *Memory
		Input          QueryAssetInput
		ExpectedAssets []*model.Asset
		ExpectedMemory *Memory
	}{
		"no-assets": {
			Memory: &Memory{
				Assets:       map[string]*model.Asset{},
				AssetVPIndex: map[string]map[string]struct{}{},
				CVEs:         map[string]*model.CVE{},
				CVEVPIndex:   map[string]map[string]struct{}{},
			},
			Input: QueryAssetInput{
				VP: nil,
			},
			ExpectedAssets: []*model.Asset{},
			ExpectedMemory: &Memory{
				Assets:       map[string]*model.Asset{},
				AssetVPIndex: map[string]map[string]struct{}{},
				CVEs:         map[string]*model.CVE{},
				CVEVPIndex:   map[string]map[string]struct{}{},
			},
		},
		"multiple-assets": {
			Memory: &Memory{
				Assets: map[string]*model.Asset{
					"asset-1": {
						ID:           "asset-1",
						Name:         "Asset 1",
						CPE23:        "cpe:2.3:a:fake:asset:1:*:*:*:*:*:*:*",
						Dependents:   []*model.Asset{},
						Dependencies: []*model.Asset{},
						CVEs:         []*model.CVE{},
					},
					"asset-2": {
						ID:           "asset-2",
						Name:         "Asset 2",
						CPE23:        "cpe:2.3:a:fake:asset:2:*:*:*:*:*:*:*",
						Dependents:   []*model.Asset{},
						Dependencies: []*model.Asset{},
						CVEs:         []*model.CVE{},
					},
				},
				AssetVPIndex: map[string]map[string]struct{}{
					"fake:asset": {
						"asset-1": {},
						"asset-2": {},
					},
				},
				CVEs:       map[string]*model.CVE{},
				CVEVPIndex: map[string]map[string]struct{}{},
			},
			Input: QueryAssetInput{
				VP: nil,
			},
			ExpectedAssets: []*model.Asset{
				{
					ID:           "asset-1",
					Name:         "Asset 1",
					CPE23:        "cpe:2.3:a:fake:asset:1:*:*:*:*:*:*:*",
					Dependents:   []*model.Asset{},
					Dependencies: []*model.Asset{},
					CVEs:         []*model.CVE{},
				}, {
					ID:           "asset-2",
					Name:         "Asset 2",
					CPE23:        "cpe:2.3:a:fake:asset:2:*:*:*:*:*:*:*",
					Dependents:   []*model.Asset{},
					Dependencies: []*model.Asset{},
					CVEs:         []*model.CVE{},
				},
			},
			ExpectedMemory: &Memory{
				Assets: map[string]*model.Asset{
					"asset-1": {
						ID:           "asset-1",
						Name:         "Asset 1",
						CPE23:        "cpe:2.3:a:fake:asset:1:*:*:*:*:*:*:*",
						Dependents:   []*model.Asset{},
						Dependencies: []*model.Asset{},
						CVEs:         []*model.CVE{},
					},
					"asset-2": {
						ID:           "asset-2",
						Name:         "Asset 2",
						CPE23:        "cpe:2.3:a:fake:asset:2:*:*:*:*:*:*:*",
						Dependents:   []*model.Asset{},
						Dependencies: []*model.Asset{},
						CVEs:         []*model.CVE{},
					},
				},
				AssetVPIndex: map[string]map[string]struct{}{
					"fake:asset": {
						"asset-1": {},
						"asset-2": {},
					},
				},
				CVEs:       map[string]*model.CVE{},
				CVEVPIndex: map[string]map[string]struct{}{},
			},
		},
		"indexed-asset": {
			Memory: &Memory{
				Assets: map[string]*model.Asset{
					"asset-1": {
						ID:           "asset-1",
						Name:         "Asset 1",
						CPE23:        "cpe:2.3:a:fake:asset:1:*:*:*:*:*:*:*",
						Dependents:   []*model.Asset{},
						Dependencies: []*model.Asset{},
						CVEs:         []*model.CVE{},
					},
					"asset-2": {
						ID:           "asset-2",
						Name:         "Asset 2",
						CPE23:        "cpe:2.3:a:fake\\_new:asset:2:*:*:*:*:*:*:*",
						Dependents:   []*model.Asset{},
						Dependencies: []*model.Asset{},
						CVEs:         []*model.CVE{},
					},
				},
				AssetVPIndex: map[string]map[string]struct{}{
					"fake:asset": {
						"asset-1": {},
					},
					"fake\\_new:asset": {
						"asset-2": {},
					},
				},
				CVEs:       map[string]*model.CVE{},
				CVEVPIndex: map[string]map[string]struct{}{},
			},
			Input: QueryAssetInput{
				VP: ptr("fake\\_new:asset"),
			},
			ExpectedAssets: []*model.Asset{
				{
					ID:           "asset-2",
					Name:         "Asset 2",
					CPE23:        "cpe:2.3:a:fake\\_new:asset:2:*:*:*:*:*:*:*",
					Dependents:   []*model.Asset{},
					Dependencies: []*model.Asset{},
					CVEs:         []*model.CVE{},
				},
			},
			ExpectedMemory: &Memory{
				Assets: map[string]*model.Asset{
					"asset-1": {
						ID:           "asset-1",
						Name:         "Asset 1",
						CPE23:        "cpe:2.3:a:fake:asset:1:*:*:*:*:*:*:*",
						Dependents:   []*model.Asset{},
						Dependencies: []*model.Asset{},
						CVEs:         []*model.CVE{},
					},
					"asset-2": {
						ID:           "asset-2",
						Name:         "Asset 2",
						CPE23:        "cpe:2.3:a:fake\\_new:asset:2:*:*:*:*:*:*:*",
						Dependents:   []*model.Asset{},
						Dependencies: []*model.Asset{},
						CVEs:         []*model.CVE{},
					},
				},
				AssetVPIndex: map[string]map[string]struct{}{
					"fake:asset": {
						"asset-1": {},
					},
					"fake\\_new:asset": {
						"asset-2": {},
					},
				},
				CVEs:       map[string]*model.CVE{},
				CVEVPIndex: map[string]map[string]struct{}{},
			},
		},
		"indexed-vp-wildcard-assets": {
			Memory: &Memory{
				Assets: map[string]*model.Asset{
					"asset-1": {
						ID:           "asset-1",
						Name:         "Asset 1",
						CPE23:        "cpe:2.3:a:fake:asset:*:*:*:*:*:*:*:*",
						Dependents:   []*model.Asset{},
						Dependencies: []*model.Asset{},
						CVEs:         []*model.CVE{},
					},
					"asset-2": {
						ID:           "asset-2",
						Name:         "Asset 2",
						CPE23:        "cpe:2.3:a:other:asset:*:*:*:*:*:*:*:*",
						Dependents:   []*model.Asset{},
						Dependencies: []*model.Asset{},
						CVEs:         []*model.CVE{},
					},
				},
				AssetVPIndex: map[string]map[string]struct{}{
					"fake:asset": {
						"asset-1": {},
					},
					"other:asset": {
						"asset-2": {},
					},
				},
				CVEs:       map[string]*model.CVE{},
				CVEVPIndex: map[string]map[string]struct{}{},
			},
			Input: QueryAssetInput{
				VP: ptr("*:asset"),
			},
			ExpectedAssets: []*model.Asset{
				{
					ID:           "asset-1",
					Name:         "Asset 1",
					CPE23:        "cpe:2.3:a:fake:asset:*:*:*:*:*:*:*:*",
					Dependents:   []*model.Asset{},
					Dependencies: []*model.Asset{},
					CVEs:         []*model.CVE{},
				}, {
					ID:           "asset-2",
					Name:         "Asset 2",
					CPE23:        "cpe:2.3:a:other:asset:*:*:*:*:*:*:*:*",
					Dependents:   []*model.Asset{},
					Dependencies: []*model.Asset{},
					CVEs:         []*model.CVE{},
				},
			},
			ExpectedMemory: &Memory{
				Assets: map[string]*model.Asset{
					"asset-1": {
						ID:           "asset-1",
						Name:         "Asset 1",
						CPE23:        "cpe:2.3:a:fake:asset:*:*:*:*:*:*:*:*",
						Dependents:   []*model.Asset{},
						Dependencies: []*model.Asset{},
						CVEs:         []*model.CVE{},
					},
					"asset-2": {
						ID:           "asset-2",
						Name:         "Asset 2",
						CPE23:        "cpe:2.3:a:other:asset:*:*:*:*:*:*:*:*",
						Dependents:   []*model.Asset{},
						Dependencies: []*model.Asset{},
						CVEs:         []*model.CVE{},
					},
				},
				AssetVPIndex: map[string]map[string]struct{}{
					"fake:asset": {
						"asset-1": {},
					},
					"other:asset": {
						"asset-2": {},
					},
				},
				CVEs:       map[string]*model.CVE{},
				CVEVPIndex: map[string]map[string]struct{}{},
			},
		},
	}

	for testname, tt := range tests {
		t.Run(testname, func(t *testing.T) {
			assert := assert.New(t)

			assets := tt.Memory.QueryAssets(tt.Input)

			assert.ElementsMatch(tt.ExpectedAssets, assets)

			// Check modified input/output does not affect database
			alter(tt.Input)
			alter(assets)
			assertEqual(tt.ExpectedMemory, tt.Memory, assert)
		})
	}
}

func TestMemoryAddAsset(t *testing.T) {
	t.Parallel()

	var tests = map[string]struct {
		Memory         *Memory
		Input          AddAssetInput
		ExpectedErr    error
		ExpectedMemory *Memory
	}{
		"asset-exist": {
			Memory: &Memory{
				Assets: map[string]*model.Asset{
					"asset": {
						ID:           "asset",
						Name:         "Asset",
						CPE23:        "cpe:2.3:a:fake:asset:*:*:*:*:*:*:*:*",
						Dependents:   []*model.Asset{},
						Dependencies: []*model.Asset{},
						CVEs:         []*model.CVE{},
					},
				},
				AssetVPIndex: map[string]map[string]struct{}{
					"fake:asset": {
						"asset": {},
					},
				},
				CVEs:       map[string]*model.CVE{},
				CVEVPIndex: map[string]map[string]struct{}{},
			},
			Input: AddAssetInput{
				ID:           "asset",
				Name:         "Asset",
				CPE23:        "cpe:2.3:a:fake:asset:*:*:*:*:*:*:*:*",
				Dependencies: nil,
			},
			ExpectedErr: &ErrAlreadyExist{
				K: KeyAsset,
				V: "asset",
			},
			ExpectedMemory: &Memory{
				Assets: map[string]*model.Asset{
					"asset": {
						ID:           "asset",
						Name:         "Asset",
						CPE23:        "cpe:2.3:a:fake:asset:*:*:*:*:*:*:*:*",
						Dependents:   []*model.Asset{},
						Dependencies: []*model.Asset{},
						CVEs:         []*model.CVE{},
					},
				},
				AssetVPIndex: map[string]map[string]struct{}{
					"fake:asset": {
						"asset": {},
					},
				},
				CVEs:       map[string]*model.CVE{},
				CVEVPIndex: map[string]map[string]struct{}{},
			},
		},
		"dependent-not-exist": {
			Memory: &Memory{
				Assets:       map[string]*model.Asset{},
				AssetVPIndex: map[string]map[string]struct{}{},
				CVEs:         map[string]*model.CVE{},
				CVEVPIndex:   map[string]map[string]struct{}{},
			},
			Input: AddAssetInput{
				ID:    "asset",
				Name:  "Asset",
				CPE23: "cpe:2.3:a:fake:asset:*:*:*:*:*:*:*:*",
				Dependents: []AddAssetDepInput{
					{
						ID: "unexisting-asset",
					},
				},
				Dependencies: []AddAssetDepInput{},
			},
			ExpectedErr: &ErrNotExist{
				K: KeyAsset,
				V: "unexisting-asset",
			},
			ExpectedMemory: &Memory{
				Assets:       map[string]*model.Asset{},
				AssetVPIndex: map[string]map[string]struct{}{},
				CVEs:         map[string]*model.CVE{},
				CVEVPIndex:   map[string]map[string]struct{}{},
			},
		},
		"dependency-not-exist": {
			Memory: &Memory{
				Assets:       map[string]*model.Asset{},
				AssetVPIndex: map[string]map[string]struct{}{},
				CVEs:         map[string]*model.CVE{},
				CVEVPIndex:   map[string]map[string]struct{}{},
			},
			Input: AddAssetInput{
				ID:    "asset",
				Name:  "Asset",
				CPE23: "cpe:2.3:a:fake:asset:*:*:*:*:*:*:*:*",
				Dependencies: []AddAssetDepInput{
					{
						ID: "unexisting-asset",
					},
				},
			},
			ExpectedErr: &ErrNotExist{
				K: KeyAsset,
				V: "unexisting-asset",
			},
			ExpectedMemory: &Memory{
				Assets:       map[string]*model.Asset{},
				AssetVPIndex: map[string]map[string]struct{}{},
				CVEs:         map[string]*model.CVE{},
				CVEVPIndex:   map[string]map[string]struct{}{},
			},
		},
		"new-asset": {
			Memory: &Memory{
				Assets: map[string]*model.Asset{
					"asset-dependent": {
						ID:           "asset-dependent",
						Name:         "Asset Dependent",
						CPE23:        "cpe:2.3:a:fake:asset:*:dependent:*:*:*:*:*:*",
						Dependents:   []*model.Asset{},
						Dependencies: []*model.Asset{},
						CVEs:         []*model.CVE{},
					},
					"asset-dependency-1": {
						ID:         "asset-dependency-1",
						Name:       "Asset Dependency 1",
						CPE23:      "cpe:2.3:a:fake:asset:1:dependency:*:*:*:*:*:*",
						Dependents: []*model.Asset{},
						Dependencies: []*model.Asset{
							{
								ID: "asset-dependency-2",
							},
						},
						CVEs: []*model.CVE{},
					},
					"asset-dependency-2": {
						ID:    "asset-dependency-2",
						Name:  "Asset Dependency 2",
						CPE23: "cpe:2.3:a:fake:asset:2:dependency:*:*:*:*:*:*",
						Dependents: []*model.Asset{
							{
								ID: "asset-dependency-1",
							},
						},
						Dependencies: []*model.Asset{},
						CVEs:         []*model.CVE{},
					},
				},
				AssetVPIndex: map[string]map[string]struct{}{
					"fake:asset": {
						"asset-dependent":    {},
						"asset-dependency-1": {},
						"asset-dependency-2": {},
					},
				},
				CVEs: map[string]*model.CVE{},
			},
			Input: AddAssetInput{
				ID:    "asset",
				Name:  "Asset",
				CPE23: "cpe:2.3:a:fake\\_new:asset:*:*:*:*:*:*:*:*",
				Dependents: []AddAssetDepInput{
					{
						ID: "asset-dependent",
					},
				},
				Dependencies: []AddAssetDepInput{
					{
						ID: "asset-dependency-1",
					}, {
						ID: "asset-dependency-2",
					},
				},
			},
			ExpectedErr: nil,
			ExpectedMemory: &Memory{
				Assets: map[string]*model.Asset{
					"asset-dependent": {
						ID:         "asset-dependent",
						Name:       "Asset Dependent",
						CPE23:      "cpe:2.3:a:fake:asset:*:dependent:*:*:*:*:*:*",
						Dependents: []*model.Asset{},
						Dependencies: []*model.Asset{
							{
								ID: "asset",
							},
						},
						CVEs: []*model.CVE{},
					},
					"asset": {
						ID:    "asset",
						Name:  "Asset",
						CPE23: "cpe:2.3:a:fake\\_new:asset:*:*:*:*:*:*:*:*",
						Dependents: []*model.Asset{
							{
								ID: "asset-dependent",
							},
						},
						Dependencies: []*model.Asset{
							{
								ID: "asset-dependency-1",
							}, {
								ID: "asset-dependency-2",
							},
						},
						CVEs: []*model.CVE{},
					},
					"asset-dependency-1": {
						ID:    "asset-dependency-1",
						Name:  "Asset Dependency 1",
						CPE23: "cpe:2.3:a:fake:asset:1:dependency:*:*:*:*:*:*",
						Dependents: []*model.Asset{
							{
								ID: "asset",
							},
						},
						Dependencies: []*model.Asset{
							{
								ID: "asset-dependency-2",
							},
						},
						CVEs: []*model.CVE{},
					},
					"asset-dependency-2": {
						ID:    "asset-dependency-2",
						Name:  "Asset Dependency 2",
						CPE23: "cpe:2.3:a:fake:asset:2:dependency:*:*:*:*:*:*",
						Dependents: []*model.Asset{
							{
								ID: "asset-dependency-1",
							}, {
								ID: "asset",
							},
						},
						Dependencies: []*model.Asset{},
						CVEs:         []*model.CVE{},
					},
				},
				AssetVPIndex: map[string]map[string]struct{}{
					"fake:asset": {
						"asset-dependent":    {},
						"asset-dependency-1": {},
						"asset-dependency-2": {},
					},
					"fake\\_new:asset": {
						"asset": {},
					},
				},
				CVEs: map[string]*model.CVE{},
			},
		},
		"asset-dependent-already-exist": {
			Memory: &Memory{
				Assets: map[string]*model.Asset{
					"asset-dependent": {
						ID:         "asset-dependent",
						Name:       "Asset Dependent",
						CPE23:      "cpe:2.3:a:fake:asset:*:*:*:*:*:*:*:*",
						Dependents: []*model.Asset{},
						Dependencies: []*model.Asset{
							{
								ID: "asset",
							},
						},
						CVEs: []*model.CVE{},
					},
					"asset": {
						ID:    "asset",
						Name:  "Asset",
						CPE23: "cpe:2.3:a:fake:asset:*:*:*:*:*:*:*:*",
						Dependents: []*model.Asset{
							{
								ID: "asset-dependent",
							},
						},
						Dependencies: []*model.Asset{},
						CVEs:         []*model.CVE{},
					},
				},
				AssetVPIndex: map[string]map[string]struct{}{
					"fake:asset": {
						"asset":           {},
						"asset-dependent": {},
					},
				},
				CVEs:       map[string]*model.CVE{},
				CVEVPIndex: map[string]map[string]struct{}{},
			},
			Input: AddAssetInput{
				ID:    "asset-new-dependent",
				Name:  "Asset New Dependent",
				CPE23: "cpe:2.3:a:fake:asset:*:*:*:*:*:*:*:*",
				Dependencies: []AddAssetDepInput{
					{
						ID: "asset",
					},
				},
			},
			ExpectedErr: nil,
			ExpectedMemory: &Memory{
				Assets: map[string]*model.Asset{
					"asset-dependent": {
						ID:         "asset-dependent",
						Name:       "Asset Dependent",
						CPE23:      "cpe:2.3:a:fake:asset:*:*:*:*:*:*:*:*",
						Dependents: []*model.Asset{},
						Dependencies: []*model.Asset{
							{
								ID: "asset",
							},
						},
						CVEs: []*model.CVE{},
					},
					"asset": {
						ID:    "asset",
						Name:  "Asset",
						CPE23: "cpe:2.3:a:fake:asset:*:*:*:*:*:*:*:*",
						Dependents: []*model.Asset{
							{
								ID: "asset-dependent",
							}, {
								ID: "asset-new-dependent",
							},
						},
						Dependencies: []*model.Asset{},
						CVEs:         []*model.CVE{},
					},
					"asset-new-dependent": {
						ID:         "asset-new-dependent",
						Name:       "Asset New Dependent",
						CPE23:      "cpe:2.3:a:fake:asset:*:*:*:*:*:*:*:*",
						Dependents: []*model.Asset{},
						Dependencies: []*model.Asset{
							{
								ID: "asset",
							},
						},
						CVEs: []*model.CVE{},
					},
				},
				AssetVPIndex: map[string]map[string]struct{}{
					"fake:asset": {
						"asset":               {},
						"asset-dependent":     {},
						"asset-new-dependent": {},
					},
				},
				CVEs:       map[string]*model.CVE{},
				CVEVPIndex: map[string]map[string]struct{}{},
			},
		},
	}

	for testname, tt := range tests {
		t.Run(testname, func(t *testing.T) {
			assert := assert.New(t)

			err := tt.Memory.AddAsset(tt.Input)

			assert.Equal(tt.ExpectedErr, err)
			assertEqual(tt.ExpectedMemory, tt.Memory, assert)

			// Check modified input/output does not affect database
			alter(tt.Input)
			assertEqual(tt.ExpectedMemory, tt.Memory, assert)
		})
	}
}

// TODO check if can do a multigraph
func TestMemoryUpdateAsset(t *testing.T) {
	t.Parallel()

	var tests = map[string]struct {
		Memory         *Memory
		Input          UpdateAssetInput
		ExpectedErr    error
		ExpectedMemory *Memory
	}{
		"asset-not-exist": {
			Memory: &Memory{
				Assets:       map[string]*model.Asset{},
				AssetVPIndex: map[string]map[string]struct{}{},
				CVEs:         map[string]*model.CVE{},
				CVEVPIndex:   map[string]map[string]struct{}{},
			},
			Input: UpdateAssetInput{
				ID:           "asset",
				Name:         nil,
				CPE23:        nil,
				Dependencies: nil,
				CVEs:         nil,
			},
			ExpectedErr: &ErrNotExist{
				K: KeyAsset,
				V: "asset",
			},
			ExpectedMemory: &Memory{
				Assets:       map[string]*model.Asset{},
				AssetVPIndex: map[string]map[string]struct{}{},
				CVEs:         map[string]*model.CVE{},
				CVEVPIndex:   map[string]map[string]struct{}{},
			},
		},
		"dependent-not-exist": {
			Memory: &Memory{
				Assets: map[string]*model.Asset{
					"asset": {
						ID:           "asset",
						Name:         "Asset",
						CPE23:        "cpe:2.3:a:fake:asset:*:*:*:*:*:*:*:*",
						Dependents:   []*model.Asset{},
						Dependencies: []*model.Asset{},
						CVEs:         []*model.CVE{},
					},
				},
				AssetVPIndex: map[string]map[string]struct{}{
					"fake:asset": {
						"asset": {},
					},
				},
				CVEs:       map[string]*model.CVE{},
				CVEVPIndex: map[string]map[string]struct{}{},
			},
			Input: UpdateAssetInput{
				ID:    "asset",
				Name:  nil,
				CPE23: nil,
				Dependents: []UpdateAssetDepInput{
					{
						ID: "asset-dependent",
					},
				},
				Dependencies: nil,
				CVEs:         nil,
			},
			ExpectedErr: &ErrNotExist{
				K: KeyAsset,
				V: "asset-dependent",
			},
			ExpectedMemory: &Memory{
				Assets: map[string]*model.Asset{
					"asset": {
						ID:           "asset",
						Name:         "Asset",
						CPE23:        "cpe:2.3:a:fake:asset:*:*:*:*:*:*:*:*",
						Dependents:   []*model.Asset{},
						Dependencies: []*model.Asset{},
						CVEs:         []*model.CVE{},
					},
				},
				AssetVPIndex: map[string]map[string]struct{}{
					"fake:asset": {
						"asset": {},
					},
				},
				CVEs:       map[string]*model.CVE{},
				CVEVPIndex: map[string]map[string]struct{}{},
			},
		},
		"dependency-not-exist": {
			Memory: &Memory{
				Assets: map[string]*model.Asset{
					"asset": {
						ID:           "asset",
						Name:         "Asset",
						CPE23:        "cpe:2.3:a:fake:asset:*:*:*:*:*:*:*:*",
						Dependents:   []*model.Asset{},
						Dependencies: []*model.Asset{},
						CVEs:         []*model.CVE{},
					},
				},
				AssetVPIndex: map[string]map[string]struct{}{
					"fake:asset": {
						"asset": {},
					},
				},
				CVEs:       map[string]*model.CVE{},
				CVEVPIndex: map[string]map[string]struct{}{},
			},
			Input: UpdateAssetInput{
				ID:    "asset",
				Name:  nil,
				CPE23: nil,
				Dependencies: []UpdateAssetDepInput{
					{
						ID: "asset-dependency",
					},
				},
				CVEs: nil,
			},
			ExpectedErr: &ErrNotExist{
				K: KeyAsset,
				V: "asset-dependency",
			},
			ExpectedMemory: &Memory{
				Assets: map[string]*model.Asset{
					"asset": {
						ID:           "asset",
						Name:         "Asset",
						CPE23:        "cpe:2.3:a:fake:asset:*:*:*:*:*:*:*:*",
						Dependents:   []*model.Asset{},
						Dependencies: []*model.Asset{},
						CVEs:         []*model.CVE{},
					},
				},
				AssetVPIndex: map[string]map[string]struct{}{
					"fake:asset": {
						"asset": {},
					},
				},
				CVEs:       map[string]*model.CVE{},
				CVEVPIndex: map[string]map[string]struct{}{},
			},
		},
		"cve-not-exist": {
			Memory: &Memory{
				Assets: map[string]*model.Asset{
					"asset": {
						ID:           "asset",
						Name:         "Asset",
						CPE23:        "cpe:2.3:a:fake:asset:*:*:*:*:*:*:*:*",
						Dependents:   []*model.Asset{},
						Dependencies: []*model.Asset{},
						CVEs:         []*model.CVE{},
					},
				},
				AssetVPIndex: map[string]map[string]struct{}{
					"fake:asset": {
						"asset": {},
					},
				},
				CVEs:       map[string]*model.CVE{},
				CVEVPIndex: map[string]map[string]struct{}{},
			},
			Input: UpdateAssetInput{
				ID:           "asset",
				Name:         nil,
				CPE23:        nil,
				Dependencies: nil,
				CVEs: []UpdateAssetCVEsInput{
					{
						ID: "cve",
					},
				},
			},
			ExpectedErr: &ErrNotExist{
				K: KeyCVE,
				V: "cve",
			},
			ExpectedMemory: &Memory{
				Assets: map[string]*model.Asset{
					"asset": {
						ID:           "asset",
						Name:         "Asset",
						CPE23:        "cpe:2.3:a:fake:asset:*:*:*:*:*:*:*:*",
						Dependents:   []*model.Asset{},
						Dependencies: []*model.Asset{},
						CVEs:         []*model.CVE{},
					},
				},
				AssetVPIndex: map[string]map[string]struct{}{
					"fake:asset": {
						"asset": {},
					},
				},
				CVEs:       map[string]*model.CVE{},
				CVEVPIndex: map[string]map[string]struct{}{},
			},
		},
		"new-name": {
			Memory: &Memory{
				Assets: map[string]*model.Asset{
					"asset": {
						ID:           "asset",
						Name:         "Asset",
						CPE23:        "cpe:2.3:a:fake:asset:*:*:*:*:*:*:*:*",
						Dependents:   []*model.Asset{},
						Dependencies: []*model.Asset{},
						CVEs:         []*model.CVE{},
					},
				},
				AssetVPIndex: map[string]map[string]struct{}{
					"fake:asset": {
						"asset": {},
					},
				},
				CVEs:       map[string]*model.CVE{},
				CVEVPIndex: map[string]map[string]struct{}{},
			},
			Input: UpdateAssetInput{
				ID:           "asset",
				Name:         ptr("New Asset"),
				CPE23:        nil,
				Dependencies: nil,
				CVEs:         nil,
			},
			ExpectedErr: nil,
			ExpectedMemory: &Memory{
				Assets: map[string]*model.Asset{
					"asset": {
						ID:           "asset",
						Name:         "New Asset",
						CPE23:        "cpe:2.3:a:fake:asset:*:*:*:*:*:*:*:*",
						Dependents:   []*model.Asset{},
						Dependencies: []*model.Asset{},
						CVEs:         []*model.CVE{},
					},
				},
				AssetVPIndex: map[string]map[string]struct{}{
					"fake:asset": {
						"asset": {},
					},
				},
				CVEs:       map[string]*model.CVE{},
				CVEVPIndex: map[string]map[string]struct{}{},
			},
		},
		"new-cpe23": {
			Memory: &Memory{
				Assets: map[string]*model.Asset{
					"asset": {
						ID:           "asset",
						Name:         "Asset",
						CPE23:        "cpe:2.3:a:fake:asset:1:*:*:*:*:*:*:*",
						Dependents:   []*model.Asset{},
						Dependencies: []*model.Asset{},
						CVEs:         []*model.CVE{},
					},
				},
				AssetVPIndex: map[string]map[string]struct{}{
					"fake:asset": {
						"asset": {},
					},
				},
				CVEs:       map[string]*model.CVE{},
				CVEVPIndex: map[string]map[string]struct{}{},
			},
			Input: UpdateAssetInput{
				ID:           "asset",
				Name:         nil,
				CPE23:        ptr("cpe:2.3:a:fake\\_other:asset:2:*:*:*:*:*:*:*"),
				Dependents:   nil,
				Dependencies: nil,
				CVEs:         nil,
			},
			ExpectedErr: nil,
			ExpectedMemory: &Memory{
				Assets: map[string]*model.Asset{
					"asset": {
						ID:           "asset",
						Name:         "Asset",
						CPE23:        "cpe:2.3:a:fake\\_other:asset:2:*:*:*:*:*:*:*",
						Dependents:   []*model.Asset{},
						Dependencies: []*model.Asset{},
						CVEs:         []*model.CVE{},
					},
				},
				AssetVPIndex: map[string]map[string]struct{}{
					"fake\\_other:asset": {
						"asset": {},
					},
				},
				CVEs:       map[string]*model.CVE{},
				CVEVPIndex: map[string]map[string]struct{}{},
			},
		},
		"new-dependent": {
			Memory: &Memory{
				Assets: map[string]*model.Asset{
					"asset": {
						ID:           "asset",
						Name:         "Asset",
						CPE23:        "cpe:2.3:a:fake:asset:*:*:*:*:*:*:*:*",
						Dependents:   []*model.Asset{},
						Dependencies: []*model.Asset{},
						CVEs:         []*model.CVE{},
					},
					"asset-dependent": {
						ID:           "asset-dependent",
						Name:         "Asset Dependent",
						CPE23:        "cpe:2.3:a:fake:asset:*:dependent:*:*:*:*:*:*",
						Dependents:   []*model.Asset{},
						Dependencies: []*model.Asset{},
						CVEs:         []*model.CVE{},
					},
				},
				AssetVPIndex: map[string]map[string]struct{}{
					"fake:asset": {
						"asset":           {},
						"asset-dependent": {},
					},
				},
				CVEs:       map[string]*model.CVE{},
				CVEVPIndex: map[string]map[string]struct{}{},
			},
			Input: UpdateAssetInput{
				ID:    "asset",
				Name:  nil,
				CPE23: nil,
				Dependents: []UpdateAssetDepInput{
					{
						ID: "asset-dependent",
					},
				},
				Dependencies: nil,
				CVEs:         nil,
			},
			ExpectedErr: nil,
			ExpectedMemory: &Memory{
				Assets: map[string]*model.Asset{
					"asset": {
						ID:    "asset",
						Name:  "Asset",
						CPE23: "cpe:2.3:a:fake:asset:*:*:*:*:*:*:*:*",
						Dependents: []*model.Asset{
							{
								ID: "asset-dependent",
							},
						},
						Dependencies: []*model.Asset{},
						CVEs:         []*model.CVE{},
					},
					"asset-dependent": {
						ID:         "asset-dependent",
						Name:       "Asset Dependent",
						CPE23:      "cpe:2.3:a:fake:asset:*:dependent:*:*:*:*:*:*",
						Dependents: []*model.Asset{},
						Dependencies: []*model.Asset{
							{
								ID: "asset",
							},
						},
						CVEs: []*model.CVE{},
					},
				},
				AssetVPIndex: map[string]map[string]struct{}{
					"fake:asset": {
						"asset":           {},
						"asset-dependent": {},
					},
				},
				CVEs:       map[string]*model.CVE{},
				CVEVPIndex: map[string]map[string]struct{}{},
			},
		},
		"new-dependent-already-existing": {
			Memory: &Memory{
				Assets: map[string]*model.Asset{
					"asset-dependent": {
						ID:         "asset-dependent",
						Name:       "Asset Dependent",
						CPE23:      "cpe:2.3:a:fake:asset:*:dependent:*:*:*:*:*:*",
						Dependents: []*model.Asset{},
						Dependencies: []*model.Asset{
							{
								ID: "asset",
							},
						},
						CVEs: []*model.CVE{},
					},
					"asset": {
						ID:    "asset",
						Name:  "Asset",
						CPE23: "cpe:2.3:a:fake:asset:*:*:*:*:*:*:*:*",
						Dependents: []*model.Asset{
							{
								ID: "asset-dependent",
							},
						},
						Dependencies: []*model.Asset{},
						CVEs:         []*model.CVE{},
					},
					"asset-future-dependent": {
						ID:           "asset-future-dependent",
						Name:         "Asset Future Dependent",
						CPE23:        "cpe:2.3:a:fake:asset:*:dependent:*:*:*:*:*:*",
						Dependents:   []*model.Asset{},
						Dependencies: []*model.Asset{},
						CVEs:         []*model.CVE{},
					},
				},
				AssetVPIndex: map[string]map[string]struct{}{
					"fake:asset": {
						"asset":                  {},
						"asset-dependent":        {},
						"asset-future-dependent": {},
					},
				},
				CVEs:       map[string]*model.CVE{},
				CVEVPIndex: map[string]map[string]struct{}{},
			},
			Input: UpdateAssetInput{
				ID:    "asset",
				Name:  nil,
				CPE23: nil,
				Dependents: []UpdateAssetDepInput{
					{
						ID: "asset-future-dependent",
					},
				},
				Dependencies: nil,
				CVEs:         nil,
			},
			ExpectedErr: nil,
			ExpectedMemory: &Memory{
				Assets: map[string]*model.Asset{
					"asset-dependent": {
						ID:           "asset-dependent",
						Name:         "Asset Dependent",
						CPE23:        "cpe:2.3:a:fake:asset:*:dependent:*:*:*:*:*:*",
						Dependents:   []*model.Asset{},
						Dependencies: []*model.Asset{},
						CVEs:         []*model.CVE{},
					},
					"asset": {
						ID:    "asset",
						Name:  "Asset",
						CPE23: "cpe:2.3:a:fake:asset:*:*:*:*:*:*:*:*",
						Dependents: []*model.Asset{
							{
								ID: "asset-future-dependent",
							},
						},
						Dependencies: []*model.Asset{},
						CVEs:         []*model.CVE{},
					},
					"asset-future-dependent": {
						ID:         "asset-future-dependent",
						Name:       "Asset Future Dependent",
						CPE23:      "cpe:2.3:a:fake:asset:*:dependent:*:*:*:*:*:*",
						Dependents: []*model.Asset{},
						Dependencies: []*model.Asset{
							{
								ID: "asset",
							},
						},
						CVEs: []*model.CVE{},
					},
				},
				AssetVPIndex: map[string]map[string]struct{}{
					"fake:asset": {
						"asset":                  {},
						"asset-dependent":        {},
						"asset-future-dependent": {},
					},
				},
				CVEs:       map[string]*model.CVE{},
				CVEVPIndex: map[string]map[string]struct{}{},
			},
		},
		"new-dependencies": {
			Memory: &Memory{
				Assets: map[string]*model.Asset{
					"asset": {
						ID:         "asset",
						Name:       "Asset",
						CPE23:      "cpe:2.3:a:fake:asset:*:*:*:*:*:*:*:*",
						Dependents: []*model.Asset{},
						Dependencies: []*model.Asset{
							{
								ID: "asset-dependency-1",
							}, {
								ID: "asset-dependency-3",
							},
						},
						CVEs: []*model.CVE{},
					},
					"asset-dependency-1": {
						ID:    "asset-dependency-1",
						Name:  "Asset Dependency 1",
						CPE23: "cpe:2.3:a:fake:asset:1:dependency:*:*:*:*:*:*",
						Dependents: []*model.Asset{
							{
								ID: "asset",
							},
						},
						Dependencies: []*model.Asset{},
						CVEs:         []*model.CVE{},
					},
					"asset-dependency-2": {
						ID:           "asset-dependency-2",
						Name:         "Asset Dependency 2",
						CPE23:        "cpe:2.3:a:fake:asset:2:dependency:*:*:*:*:*:*",
						Dependents:   []*model.Asset{},
						Dependencies: []*model.Asset{},
						CVEs:         []*model.CVE{},
					},
					"asset-dependency-3": {
						ID:    "asset-dependency-3",
						Name:  "Asset Dependency 3",
						CPE23: "cpe:2.3:a:fake:asset:3:dependency:*:*:*:*:*:*",
						Dependents: []*model.Asset{
							{
								ID: "asset",
							},
						},
						Dependencies: []*model.Asset{},
						CVEs:         []*model.CVE{},
					},
				},
				AssetVPIndex: map[string]map[string]struct{}{
					"fake:asset": {
						"asset":              {},
						"asset-dependency-1": {},
						"asset-dependency-2": {},
						"asset-dependency-3": {},
					},
				},
				CVEs:       map[string]*model.CVE{},
				CVEVPIndex: map[string]map[string]struct{}{},
			},
			Input: UpdateAssetInput{
				ID:         "asset",
				Name:       nil,
				CPE23:      nil,
				Dependents: nil,
				Dependencies: []UpdateAssetDepInput{
					{
						ID: "asset-dependency-2",
					}, {
						ID: "asset-dependency-3",
					},
				},
				CVEs: nil,
			},
			ExpectedErr: nil,
			ExpectedMemory: &Memory{
				Assets: map[string]*model.Asset{
					"asset": {
						ID:         "asset",
						Name:       "Asset",
						CPE23:      "cpe:2.3:a:fake:asset:*:*:*:*:*:*:*:*",
						Dependents: []*model.Asset{},
						Dependencies: []*model.Asset{
							{
								ID: "asset-dependency-2",
							}, {
								ID: "asset-dependency-3",
							},
						},
						CVEs: []*model.CVE{},
					},
					"asset-dependency-1": {
						ID:           "asset-dependency-1",
						Name:         "Asset Dependency 1",
						CPE23:        "cpe:2.3:a:fake:asset:1:dependency:*:*:*:*:*:*",
						Dependents:   []*model.Asset{},
						Dependencies: []*model.Asset{},
						CVEs:         []*model.CVE{},
					},
					"asset-dependency-2": {
						ID:    "asset-dependency-2",
						Name:  "Asset Dependency 2",
						CPE23: "cpe:2.3:a:fake:asset:2:dependency:*:*:*:*:*:*",
						Dependents: []*model.Asset{
							{
								ID: "asset",
							},
						},
						Dependencies: []*model.Asset{},
						CVEs:         []*model.CVE{},
					},
					"asset-dependency-3": {
						ID:    "asset-dependency-3",
						Name:  "Asset Dependency 3",
						CPE23: "cpe:2.3:a:fake:asset:3:dependency:*:*:*:*:*:*",
						Dependents: []*model.Asset{
							{
								ID: "asset",
							},
						},
						Dependencies: []*model.Asset{},
						CVEs:         []*model.CVE{},
					},
				},
				AssetVPIndex: map[string]map[string]struct{}{
					"fake:asset": {
						"asset":              {},
						"asset-dependency-1": {},
						"asset-dependency-2": {},
						"asset-dependency-3": {},
					},
				},
				CVEs:       map[string]*model.CVE{},
				CVEVPIndex: map[string]map[string]struct{}{},
			},
		},
		"new-cves": {
			Memory: &Memory{
				Assets: map[string]*model.Asset{
					"asset": {
						ID:           "asset",
						Name:         "Asset",
						CPE23:        "cpe:2.3:a:fake:asset:*:*:*:*:*:*:*:*",
						Dependents:   []*model.Asset{},
						Dependencies: []*model.Asset{},
						CVEs: []*model.CVE{
							{
								ID: "cve-1",
							}, {
								ID: "cve-3",
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
					"cve-1": {
						ID:              "cve-1",
						PublicationDate: timeParse("2020-02-01T14:30Z"),
						LastUpdate:      timeParse("2020-02-01T14:30Z"),
						CVSS2Vector:     nil,
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
					},
					"cve-2": {
						ID:              "cve-2",
						PublicationDate: timeParse("2020-02-01T14:30Z"),
						LastUpdate:      timeParse("2020-02-01T14:30Z"),
						CVSS2Vector:     nil,
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
						Assets: []*model.Asset{},
					},
					"cve-3": {
						ID:              "cve-3",
						PublicationDate: timeParse("2020-02-17T14:30Z"),
						LastUpdate:      timeParse("2020-02-17T14:30Z"),
						CVSS2Vector:     nil,
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
					},
				},
				CVEVPIndex: map[string]map[string]struct{}{
					"fake:asset": {
						"cve-1": {},
						"cve-2": {},
						"cve-3": {},
					},
				},
			},
			Input: UpdateAssetInput{
				ID:           "asset",
				Name:         nil,
				CPE23:        nil,
				Dependents:   nil,
				Dependencies: nil,
				CVEs: []UpdateAssetCVEsInput{
					{
						ID: "cve-2",
					}, {
						ID: "cve-3",
					},
				},
			},
			ExpectedErr: nil,
			ExpectedMemory: &Memory{
				Assets: map[string]*model.Asset{
					"asset": {
						ID:           "asset",
						Name:         "Asset",
						CPE23:        "cpe:2.3:a:fake:asset:*:*:*:*:*:*:*:*",
						Dependents:   []*model.Asset{},
						Dependencies: []*model.Asset{},
						CVEs: []*model.CVE{
							{
								ID: "cve-2",
							}, {
								ID: "cve-3",
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
					"cve-1": {
						ID:              "cve-1",
						PublicationDate: timeParse("2020-02-01T14:30Z"),
						LastUpdate:      timeParse("2020-02-01T14:30Z"),
						CVSS2Vector:     nil,
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
						Assets: []*model.Asset{},
					},
					"cve-2": {
						ID:              "cve-2",
						PublicationDate: timeParse("2020-02-01T14:30Z"),
						LastUpdate:      timeParse("2020-02-01T14:30Z"),
						CVSS2Vector:     nil,
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
					},
					"cve-3": {
						ID:              "cve-3",
						PublicationDate: timeParse("2020-02-17T14:30Z"),
						LastUpdate:      timeParse("2020-02-17T14:30Z"),
						CVSS2Vector:     nil,
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
					},
				},
				CVEVPIndex: map[string]map[string]struct{}{
					"fake:asset": {
						"cve-1": {},
						"cve-2": {},
						"cve-3": {},
					},
				},
			},
		},
	}

	for testname, tt := range tests {
		t.Run(testname, func(t *testing.T) {
			assert := assert.New(t)

			err := tt.Memory.UpdateAsset(tt.Input)

			assert.Equal(tt.ExpectedErr, err)
			assertEqual(tt.ExpectedMemory, tt.Memory, assert)

			// Check modified input/output does not affect database
			alter(tt.Input)
			assertEqual(tt.ExpectedMemory, tt.Memory, assert)
		})
	}
}

func TestMemoryDeleteAsset(t *testing.T) {
	t.Parallel()

	var tests = map[string]struct {
		Memory         *Memory
		Input          DeleteAssetInput
		ExpectedErr    error
		ExpectedMemory *Memory
	}{
		"unexisting-asset": {
			Memory: &Memory{
				Assets:       map[string]*model.Asset{},
				AssetVPIndex: map[string]map[string]struct{}{},
				CVEs:         map[string]*model.CVE{},
				CVEVPIndex:   map[string]map[string]struct{}{},
			},
			Input: DeleteAssetInput{
				ID: "asset",
			},
			ExpectedErr: &ErrNotExist{
				K: KeyAsset,
				V: "asset",
			},
			ExpectedMemory: &Memory{
				Assets:       map[string]*model.Asset{},
				AssetVPIndex: map[string]map[string]struct{}{},
				CVEs:         map[string]*model.CVE{},
				CVEVPIndex:   map[string]map[string]struct{}{},
			},
		},
		"existing-asset": {
			Memory: &Memory{
				Assets: map[string]*model.Asset{
					"asset-dependent": {
						ID:         "asset-dependent",
						Name:       "Asset Dependent",
						CPE23:      "cpe:2.3:a:fake:asset:*:dependent:*:*:*:*:*:*",
						Dependents: []*model.Asset{},
						Dependencies: []*model.Asset{
							{
								ID: "asset",
							},
						},
						CVEs: []*model.CVE{},
					},
					"asset": {
						ID:    "asset",
						Name:  "Asset",
						CPE23: "cpe:2.3:a:fake:asset\\_goodbye:*:*:*:*:*:*:*:*",
						Dependents: []*model.Asset{
							{
								ID: "asset-dependent",
							},
						},
						Dependencies: []*model.Asset{
							{
								ID: "asset-dependency",
							},
						},
						CVEs: []*model.CVE{
							{
								ID: "cve",
							},
						},
					},
					"asset-dependency": {
						ID:    "asset-dependency",
						Name:  "Asset Dependency",
						CPE23: "cpe:2.3:a:fake:asset:*:dependency:*:*:*:*:*:*",
						Dependents: []*model.Asset{
							{
								ID: "asset",
							},
						},
						Dependencies: []*model.Asset{},
						CVEs:         []*model.CVE{},
					},
				},
				AssetVPIndex: map[string]map[string]struct{}{
					"fake:asset": {
						"asset-dependent":  {},
						"asset-dependency": {},
					},
					"fake:asset\\_goodbye": {
						"asset": {},
					},
				},
				CVEs: map[string]*model.CVE{
					"cve": {
						ID:              "cve",
						PublicationDate: timeParse("2020-02-01T14:30Z"),
						LastUpdate:      timeParse("2020-02-01T14:30Z"),
						CVSS2Vector:     nil,
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
					},
				},
				CVEVPIndex: map[string]map[string]struct{}{
					"fake:asset": {
						"cve": {},
					},
				},
			},
			Input: DeleteAssetInput{
				ID: "asset",
			},
			ExpectedErr: nil,
			ExpectedMemory: &Memory{
				Assets: map[string]*model.Asset{
					"asset-dependent": {
						ID:           "asset-dependent",
						Name:         "Asset Dependent",
						CPE23:        "cpe:2.3:a:fake:asset:*:dependent:*:*:*:*:*:*",
						Dependents:   []*model.Asset{},
						Dependencies: []*model.Asset{},
						CVEs:         []*model.CVE{},
					},
					"asset-dependency": {
						ID:           "asset-dependency",
						Name:         "Asset Dependency",
						CPE23:        "cpe:2.3:a:fake:asset:*:dependency:*:*:*:*:*:*",
						Dependents:   []*model.Asset{},
						Dependencies: []*model.Asset{},
						CVEs:         []*model.CVE{},
					},
				},
				AssetVPIndex: map[string]map[string]struct{}{
					"fake:asset": {
						"asset-dependent":  {},
						"asset-dependency": {},
					},
				},
				CVEs: map[string]*model.CVE{
					"cve": {
						ID:              "cve",
						PublicationDate: timeParse("2020-02-01T14:30Z"),
						LastUpdate:      timeParse("2020-02-01T14:30Z"),
						CVSS2Vector:     nil,
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
						Assets: []*model.Asset{},
					},
				},
				CVEVPIndex: map[string]map[string]struct{}{
					"fake:asset": {
						"cve": {},
					},
				},
			},
		},
	}

	for testname, tt := range tests {
		t.Run(testname, func(t *testing.T) {
			assert := assert.New(t)

			err := tt.Memory.DeleteAsset(tt.Input)

			assert.Equal(tt.ExpectedErr, err)
			assertEqual(tt.ExpectedMemory, tt.Memory, assert)

			// Check modified input/output does not affect database
			alter(tt.Input)
			assertEqual(tt.ExpectedMemory, tt.Memory, assert)
		})
	}
}

func TestMemoryGetCVE(t *testing.T) {
	t.Parallel()

	var tests = map[string]struct {
		Memory         *Memory
		Input          GetCVEInput
		ExpectedCVE    *model.CVE
		ExpectedErr    error
		ExpectedMemory *Memory
	}{
		"unexisting-cve": {
			Memory: &Memory{
				Assets:       map[string]*model.Asset{},
				AssetVPIndex: map[string]map[string]struct{}{},
				CVEs:         map[string]*model.CVE{},
				CVEVPIndex:   map[string]map[string]struct{}{},
			},
			Input: GetCVEInput{
				ID: "cve",
			},
			ExpectedCVE: nil,
			ExpectedErr: &ErrNotExist{
				K: KeyCVE,
				V: "cve",
			},
			ExpectedMemory: &Memory{
				Assets:       map[string]*model.Asset{},
				AssetVPIndex: map[string]map[string]struct{}{},
				CVEs:         map[string]*model.CVE{},
				CVEVPIndex:   map[string]map[string]struct{}{},
			},
		},
		"existing-cve": {
			Memory: &Memory{
				Assets:       map[string]*model.Asset{},
				AssetVPIndex: map[string]map[string]struct{}{},
				CVEs: map[string]*model.CVE{
					"cve": {
						ID:              "cve",
						Description:     "This is a CVE.",
						PublicationDate: timeParse("2020-02-01T14:30Z"),
						LastUpdate:      timeParse("2020-02-01T14:30Z"),
						CVSS2Vector:     nil,
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
						Assets: []*model.Asset{},
						References: []*model.Reference{
							{
								URL:       "https://example.com",
								Refsource: "MISC",
								Tags:      []string{"Third Party Advisory"},
							},
						},
					},
				},
				CVEVPIndex: map[string]map[string]struct{}{
					"fake:asset": {
						"cve": {},
					},
				},
			},
			Input: GetCVEInput{
				ID: "cve",
			},
			ExpectedCVE: &model.CVE{
				ID:              "cve",
				Description:     "This is a CVE.",
				PublicationDate: timeParse("2020-02-01T14:30Z"),
				LastUpdate:      timeParse("2020-02-01T14:30Z"),
				CVSS2Vector:     nil,
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
				Assets: []*model.Asset{},
				References: []*model.Reference{
					{
						URL:       "https://example.com",
						Refsource: "MISC",
						Tags:      []string{"Third Party Advisory"},
					},
				},
			},
			ExpectedErr: nil,
			ExpectedMemory: &Memory{
				Assets:       map[string]*model.Asset{},
				AssetVPIndex: map[string]map[string]struct{}{},
				CVEs: map[string]*model.CVE{
					"cve": {
						ID:              "cve",
						Description:     "This is a CVE.",
						PublicationDate: timeParse("2020-02-01T14:30Z"),
						LastUpdate:      timeParse("2020-02-01T14:30Z"),
						CVSS2Vector:     nil,
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
						Assets: []*model.Asset{},
						References: []*model.Reference{
							{
								URL:       "https://example.com",
								Refsource: "MISC",
								Tags:      []string{"Third Party Advisory"},
							},
						},
					},
				},
				CVEVPIndex: map[string]map[string]struct{}{
					"fake:asset": {
						"cve": {},
					},
				},
			},
		},
	}

	for testname, tt := range tests {
		t.Run(testname, func(t *testing.T) {
			assert := assert.New(t)

			cve, err := tt.Memory.GetCVE(tt.Input)

			assert.Equal(tt.ExpectedCVE, cve)
			assert.Equal(tt.ExpectedErr, err)
			assertEqual(tt.ExpectedMemory, tt.Memory, assert)

			// Check modified input/output does not affect database
			alter(tt.Input)
			alter(cve)
			assertEqual(tt.ExpectedMemory, tt.Memory, assert)
		})
	}
}

func TestMemoryQueryCVEs(t *testing.T) {
	t.Parallel()

	var tests = map[string]struct {
		Memory         *Memory
		Input          QueryCVEInput
		ExpectedCVEs   []*model.CVE
		ExpectedMemory *Memory
	}{
		"no-cves": {
			Memory: &Memory{
				Assets:       map[string]*model.Asset{},
				AssetVPIndex: map[string]map[string]struct{}{},
				CVEs:         map[string]*model.CVE{},
				CVEVPIndex:   map[string]map[string]struct{}{},
			},
			Input: QueryCVEInput{
				VP: nil,
			},
			ExpectedCVEs: []*model.CVE{},
			ExpectedMemory: &Memory{
				Assets:       map[string]*model.Asset{},
				AssetVPIndex: map[string]map[string]struct{}{},
				CVEs:         map[string]*model.CVE{},
				CVEVPIndex:   map[string]map[string]struct{}{},
			},
		},
		"multiple-cves": {
			Memory: &Memory{
				Assets:       map[string]*model.Asset{},
				AssetVPIndex: map[string]map[string]struct{}{},
				CVEs: map[string]*model.CVE{
					"cve-1": {
						ID:              "cve-1",
						PublicationDate: timeParse("2020-02-01T14:30Z"),
						LastUpdate:      timeParse("2020-02-01T14:30Z"),
						CVSS2Vector:     nil,
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
					"cve-2": {
						ID:              "cve-2",
						PublicationDate: timeParse("2020-02-01T14:30Z"),
						LastUpdate:      timeParse("2020-02-01T14:30Z"),
						CVSS2Vector:     nil,
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
						"cve-1": {},
						"cve-2": {},
					},
				},
			},
			Input: QueryCVEInput{
				VP: nil,
			},
			ExpectedCVEs: []*model.CVE{
				{
					ID:              "cve-1",
					PublicationDate: timeParse("2020-02-01T14:30Z"),
					LastUpdate:      timeParse("2020-02-01T14:30Z"),
					CVSS2Vector:     nil,
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
				}, {
					ID:              "cve-2",
					PublicationDate: timeParse("2020-02-01T14:30Z"),
					LastUpdate:      timeParse("2020-02-01T14:30Z"),
					CVSS2Vector:     nil,
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
			ExpectedMemory: &Memory{
				Assets:       map[string]*model.Asset{},
				AssetVPIndex: map[string]map[string]struct{}{},
				CVEs: map[string]*model.CVE{
					"cve-1": {
						ID:              "cve-1",
						PublicationDate: timeParse("2020-02-01T14:30Z"),
						LastUpdate:      timeParse("2020-02-01T14:30Z"),
						CVSS2Vector:     nil,
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
					"cve-2": {
						ID:              "cve-2",
						PublicationDate: timeParse("2020-02-01T14:30Z"),
						LastUpdate:      timeParse("2020-02-01T14:30Z"),
						CVSS2Vector:     nil,
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
						"cve-1": {},
						"cve-2": {},
					},
				},
			},
		},
		"indexed-cve": {
			Memory: &Memory{
				Assets:       map[string]*model.Asset{},
				AssetVPIndex: map[string]map[string]struct{}{},
				CVEs: map[string]*model.CVE{
					"cve-1": {
						ID:              "cve-1",
						PublicationDate: timeParse("2020-02-01T14:30Z"),
						LastUpdate:      timeParse("2020-02-01T14:30Z"),
						CVSS2Vector:     nil,
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
					"cve-2": {
						ID:              "cve-2",
						PublicationDate: timeParse("2020-02-01T14:30Z"),
						LastUpdate:      timeParse("2020-02-01T14:30Z"),
						CVSS2Vector:     nil,
						Configurations: []*model.Node{
							{
								Negate:   nil,
								Operator: "OR",
								Children: []*model.Node{},
								CPEMatches: []*model.CPEMatch{
									{
										Vulnerable:            true,
										CPE23:                 "cpe:2.3:a:fake\\_new:asset:*:*:*:*:*:*:*:*",
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
						"cve-1": {},
					},
					"fake\\_:asset": {
						"cve-2": {},
					},
				},
			},
			Input: QueryCVEInput{
				VP: ptr("fake:asset"),
			},
			ExpectedCVEs: []*model.CVE{
				{
					ID:              "cve-1",
					PublicationDate: timeParse("2020-02-01T14:30Z"),
					LastUpdate:      timeParse("2020-02-01T14:30Z"),
					CVSS2Vector:     nil,
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
			ExpectedMemory: &Memory{
				Assets:       map[string]*model.Asset{},
				AssetVPIndex: map[string]map[string]struct{}{},
				CVEs: map[string]*model.CVE{
					"cve-1": {
						ID:              "cve-1",
						PublicationDate: timeParse("2020-02-01T14:30Z"),
						LastUpdate:      timeParse("2020-02-01T14:30Z"),
						CVSS2Vector:     nil,
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
					"cve-2": {
						ID:              "cve-2",
						PublicationDate: timeParse("2020-02-01T14:30Z"),
						LastUpdate:      timeParse("2020-02-01T14:30Z"),
						CVSS2Vector:     nil,
						Configurations: []*model.Node{
							{
								Negate:   nil,
								Operator: "OR",
								Children: []*model.Node{},
								CPEMatches: []*model.CPEMatch{
									{
										Vulnerable:            true,
										CPE23:                 "cpe:2.3:a:fake\\_new:asset:*:*:*:*:*:*:*:*",
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
						"cve-1": {},
					},
					"fake\\_:asset": {
						"cve-2": {},
					},
				},
			},
		},
		"indexed-vp-wildcard-assets": {
			Memory: &Memory{
				Assets:       map[string]*model.Asset{},
				AssetVPIndex: map[string]map[string]struct{}{},
				CVEs: map[string]*model.CVE{
					"cve-1": {
						ID:              "cve-1",
						Description:     "CVE description 1",
						PublicationDate: timeParse("2020-05-06T09:35Z"),
						LastUpdate:      timeParse("2020-05-06T09:35Z"),
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
										CPE23:                 "cpe:2.3:a:fake:product:*:*:*:*:*:*:*:*",
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
					"cve-2": {
						ID:              "cve-2",
						Description:     "CVE description 2",
						PublicationDate: timeParse("2020-05-06T09:35Z"),
						LastUpdate:      timeParse("2020-05-06T09:35Z"),
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
										CPE23:                 "cpe:2.3:a:other:product:*:*:*:*:*:*:*:*",
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
					"fake:product": {
						"cve-1": {},
					},
					"other:product": {
						"cve-2": {},
					},
				},
			},
			Input: QueryCVEInput{
				VP: ptr("*:product"),
			},
			ExpectedCVEs: []*model.CVE{
				{
					ID:              "cve-1",
					Description:     "CVE description 1",
					PublicationDate: timeParse("2020-05-06T09:35Z"),
					LastUpdate:      timeParse("2020-05-06T09:35Z"),
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
									CPE23:                 "cpe:2.3:a:fake:product:*:*:*:*:*:*:*:*",
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
				}, {
					ID:              "cve-2",
					Description:     "CVE description 2",
					PublicationDate: timeParse("2020-05-06T09:35Z"),
					LastUpdate:      timeParse("2020-05-06T09:35Z"),
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
									CPE23:                 "cpe:2.3:a:other:product:*:*:*:*:*:*:*:*",
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
			ExpectedMemory: &Memory{
				Assets:       map[string]*model.Asset{},
				AssetVPIndex: map[string]map[string]struct{}{},
				CVEs: map[string]*model.CVE{
					"cve-1": {
						ID:              "cve-1",
						Description:     "CVE description 1",
						PublicationDate: timeParse("2020-05-06T09:35Z"),
						LastUpdate:      timeParse("2020-05-06T09:35Z"),
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
										CPE23:                 "cpe:2.3:a:fake:product:*:*:*:*:*:*:*:*",
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
					"cve-2": {
						ID:              "cve-2",
						Description:     "CVE description 2",
						PublicationDate: timeParse("2020-05-06T09:35Z"),
						LastUpdate:      timeParse("2020-05-06T09:35Z"),
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
										CPE23:                 "cpe:2.3:a:other:product:*:*:*:*:*:*:*:*",
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
					"fake:product": {
						"cve-1": {},
					},
					"other:product": {
						"cve-2": {},
					},
				},
			},
		},
	}

	for testname, tt := range tests {
		t.Run(testname, func(t *testing.T) {
			assert := assert.New(t)

			cves := tt.Memory.QueryCVEs(tt.Input)

			assert.ElementsMatch(tt.ExpectedCVEs, cves)
			assertEqual(tt.ExpectedMemory, tt.Memory, assert)

			// Check modified input/output does not affect database
			alter(tt.Input)
			assertEqual(tt.ExpectedMemory, tt.Memory, assert)
		})
	}
}

func TestMemoryAddCVE(t *testing.T) {
	t.Parallel()

	var tests = map[string]struct {
		Memory         *Memory
		Input          AddCVEInput
		ExpectedErr    error
		ExpectedMemory *Memory
	}{
		"cve-exist": {
			Memory: &Memory{
				Assets:       map[string]*model.Asset{},
				AssetVPIndex: map[string]map[string]struct{}{},
				CVEs: map[string]*model.CVE{
					"cve": {
						ID:              "cve",
						Description:     "CVE in something.",
						PublicationDate: timeParse("2020-02-01T14:30Z"),
						LastUpdate:      timeParse("2020-02-01T14:30Z"),
						CVSS2Vector:     nil,
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
			Input: AddCVEInput{
				ID:              "cve",
				Description:     "CVE in something.",
				PublicationDate: timeParse("2020-02-01T14:30Z"),
				LastUpdate:      timeParse("2020-02-01T14:30Z"),
				CVSS2Vector:     nil,
				Configurations: []AddCVENodeInput{
					{
						Negate:   nil,
						Operator: "OR",
						Children: nil,
						CPEMatches: []AddCVENodeCPEMatchInput{
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
				References: []AddCVEReferenceInput{},
			},
			ExpectedErr: &ErrAlreadyExist{
				K: KeyCVE,
				V: "cve",
			},
			ExpectedMemory: &Memory{
				Assets:       map[string]*model.Asset{},
				AssetVPIndex: map[string]map[string]struct{}{},
				CVEs: map[string]*model.CVE{
					"cve": {
						ID:              "cve",
						Description:     "CVE in something.",
						PublicationDate: timeParse("2020-02-01T14:30Z"),
						LastUpdate:      timeParse("2020-02-01T14:30Z"),
						CVSS2Vector:     nil,
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
		},
		"new-cve": {
			Memory: &Memory{
				Assets:       map[string]*model.Asset{},
				AssetVPIndex: map[string]map[string]struct{}{},
				CVEs:         map[string]*model.CVE{},
				CVEVPIndex:   map[string]map[string]struct{}{},
			},
			Input: AddCVEInput{
				ID:              "cve",
				Description:     "CVE in something.",
				PublicationDate: timeParse("2020-02-01T14:30Z"),
				LastUpdate:      timeParse("2020-02-01T14:30Z"),
				CVSS2Vector:     ptr("AV:A/AC:H/Au:S/C:P/I:P/A:C"),
				CVSS3Vector:     ptr("CVSS:3.1/AV:A/AC:H/PR:L/UI:N/S:C/C:L/I:L/A:H"),
				Configurations: []AddCVENodeInput{
					{
						Negate:   nil,
						Operator: "OR",
						Children: nil,
						CPEMatches: []AddCVENodeCPEMatchInput{
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
				References: []AddCVEReferenceInput{
					{
						URL:       "https://example.com",
						Name:      "Example reference",
						Refsource: "MISC",
						Tags:      []string{"Patch"},
					},
				},
			},
			ExpectedErr: nil,
			ExpectedMemory: &Memory{
				Assets:       map[string]*model.Asset{},
				AssetVPIndex: map[string]map[string]struct{}{},
				CVEs: map[string]*model.CVE{
					"cve": {
						ID:              "cve",
						Description:     "CVE in something.",
						PublicationDate: timeParse("2020-02-01T14:30Z"),
						LastUpdate:      timeParse("2020-02-01T14:30Z"),
						CVSS2Vector:     ptr("AV:A/AC:H/Au:S/C:P/I:P/A:C"),
						CVSS3Vector:     ptr("CVSS:3.1/AV:A/AC:H/PR:L/UI:N/S:C/C:L/I:L/A:H"),
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
						Assets: []*model.Asset{},
						References: []*model.Reference{
							{
								URL:       "https://example.com",
								Name:      "Example reference",
								Refsource: "MISC",
								Tags:      []string{"Patch"},
							},
						},
					},
				},
				CVEVPIndex: map[string]map[string]struct{}{
					"fake:asset": {
						"cve": {},
					},
				},
			},
		},
	}

	for testname, tt := range tests {
		t.Run(testname, func(t *testing.T) {
			assert := assert.New(t)

			err := tt.Memory.AddCVE(tt.Input)

			assert.Equal(tt.ExpectedErr, err)
			assertEqual(tt.ExpectedMemory, tt.Memory, assert)

			// Check modified input/output does not affect database
			alter(tt.Input)
			assertEqual(tt.ExpectedMemory, tt.Memory, assert)
		})
	}
}

func TestMemoryUpdateCVE(t *testing.T) {
	t.Parallel()

	var tests = map[string]struct {
		Memory         *Memory
		Input          UpdateCVEInput
		ExpectedErr    error
		ExpectedMemory *Memory
	}{
		"cve-not-exist": {
			Memory: &Memory{
				Assets:       map[string]*model.Asset{},
				AssetVPIndex: map[string]map[string]struct{}{},
				CVEs:         map[string]*model.CVE{},
				CVEVPIndex:   map[string]map[string]struct{}{},
			},
			Input: UpdateCVEInput{
				ID:             "cve",
				Description:    nil,
				LastUpdate:     nil,
				CVSS2Vector:    nil,
				CVSS3Vector:    nil,
				Configurations: nil,
				Assets:         nil,
			},
			ExpectedErr: &ErrNotExist{
				K: KeyCVE,
				V: "cve",
			},
			ExpectedMemory: &Memory{
				Assets:       map[string]*model.Asset{},
				AssetVPIndex: map[string]map[string]struct{}{},
				CVEs:         map[string]*model.CVE{},
				CVEVPIndex:   map[string]map[string]struct{}{},
			},
		},
		"asset-not-exist": {
			Memory: &Memory{
				Assets:       map[string]*model.Asset{},
				AssetVPIndex: map[string]map[string]struct{}{},
				CVEs: map[string]*model.CVE{
					"cve": {
						ID:              "cve",
						Description:     "CVE in something.",
						PublicationDate: timeParse("2020-02-01T14:30Z"),
						LastUpdate:      timeParse("2020-02-01T14:30Z"),
						CVSS2Vector:     ptr("AV:A/AC:H/Au:S/C:P/I:P/A:C"),
						CVSS3Vector:     ptr("CVSS:3.1/AV:A/AC:H/PR:L/UI:N/S:C/C:L/I:L/A:H"),
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
			Input: UpdateCVEInput{
				ID:             "cve",
				Description:    nil,
				LastUpdate:     nil,
				CVSS2Vector:    nil,
				CVSS3Vector:    nil,
				Configurations: nil,
				Assets: []UpdateCVEAssetInput{
					{
						ID: "asset",
					},
				},
			},
			ExpectedErr: &ErrNotExist{
				K: KeyAsset,
				V: "asset",
			},
			ExpectedMemory: &Memory{
				Assets:       map[string]*model.Asset{},
				AssetVPIndex: map[string]map[string]struct{}{},
				CVEs: map[string]*model.CVE{
					"cve": {
						ID:              "cve",
						Description:     "CVE in something.",
						PublicationDate: timeParse("2020-02-01T14:30Z"),
						LastUpdate:      timeParse("2020-02-01T14:30Z"),
						CVSS2Vector:     ptr("AV:A/AC:H/Au:S/C:P/I:P/A:C"),
						CVSS3Vector:     ptr("CVSS:3.1/AV:A/AC:H/PR:L/UI:N/S:C/C:L/I:L/A:H"),
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
		},
		"new-description": {
			Memory: &Memory{
				Assets:       map[string]*model.Asset{},
				AssetVPIndex: map[string]map[string]struct{}{},
				CVEs: map[string]*model.CVE{
					"cve": {
						ID:              "cve",
						Description:     "CVE in something.",
						PublicationDate: timeParse("2022-02-01T14:30Z"),
						LastUpdate:      timeParse("2022-02-01T14:30Z"),
						CVSS2Vector:     nil,
						Configurations:  []*model.Node{},
						Assets:          []*model.Asset{},
						References:      []*model.Reference{},
					},
				},
				CVEVPIndex: map[string]map[string]struct{}{},
			},
			Input: UpdateCVEInput{
				ID:             "cve",
				Description:    ptr("CVE in something, but new."),
				LastUpdate:     nil,
				CVSS2Vector:    nil,
				CVSS3Vector:    nil,
				Configurations: nil,
				Assets:         nil,
				References:     nil,
			},
			ExpectedErr: nil,
			ExpectedMemory: &Memory{
				Assets:       map[string]*model.Asset{},
				AssetVPIndex: map[string]map[string]struct{}{},
				CVEs: map[string]*model.CVE{
					"cve": {
						ID:              "cve",
						Description:     "CVE in something, but new.",
						PublicationDate: timeParse("2022-02-01T14:30Z"),
						LastUpdate:      timeParse("2022-02-01T14:30Z"),
						CVSS2Vector:     nil,
						Configurations:  []*model.Node{},
						Assets:          []*model.Asset{},
						References:      []*model.Reference{},
					},
				},
				CVEVPIndex: map[string]map[string]struct{}{},
			},
		},
		"new-lastUpdate": {
			Memory: &Memory{
				Assets:       map[string]*model.Asset{},
				AssetVPIndex: map[string]map[string]struct{}{},
				CVEs: map[string]*model.CVE{
					"cve": {
						ID:              "cve",
						Description:     "CVE in something.",
						PublicationDate: timeParse("2020-02-01T14:30Z"),
						LastUpdate:      timeParse("2020-02-01T14:30Z"),
						CVSS2Vector:     nil,
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
			Input: UpdateCVEInput{
				ID:             "cve",
				Description:    nil,
				LastUpdate:     ptr(timeParse("2022-02-01T14:30Z")),
				CVSS2Vector:    nil,
				CVSS3Vector:    nil,
				Configurations: nil,
				Assets:         nil,
				References:     nil,
			},
			ExpectedErr: nil,
			ExpectedMemory: &Memory{
				Assets:       map[string]*model.Asset{},
				AssetVPIndex: map[string]map[string]struct{}{},
				CVEs: map[string]*model.CVE{
					"cve": {
						ID:              "cve",
						Description:     "CVE in something.",
						PublicationDate: timeParse("2020-02-01T14:30Z"),
						LastUpdate:      timeParse("2022-02-01T14:30Z"),
						CVSS2Vector:     nil,
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
		},
		"new-cvss2vector": {
			Memory: &Memory{
				Assets:       map[string]*model.Asset{},
				AssetVPIndex: map[string]map[string]struct{}{},
				CVEs: map[string]*model.CVE{
					"cve": {
						ID:              "cve",
						Description:     "CVE in something.",
						PublicationDate: timeParse("2020-02-01T14:30Z"),
						LastUpdate:      timeParse("2020-02-01T14:30Z"),
						CVSS2Vector:     nil,
						Configurations:  []*model.Node{},
						Assets:          []*model.Asset{},
						References:      []*model.Reference{},
					},
				},
				CVEVPIndex: map[string]map[string]struct{}{},
			},
			Input: UpdateCVEInput{
				ID:             "cve",
				Description:    nil,
				LastUpdate:     nil,
				CVSS2Vector:    ptr("AV:A/AC:H/Au:S/C:P/I:P/A:C"),
				CVSS3Vector:    nil,
				Configurations: nil,
				Assets:         nil,
				References:     nil,
			},
			ExpectedErr: nil,
			ExpectedMemory: &Memory{
				Assets:       map[string]*model.Asset{},
				AssetVPIndex: map[string]map[string]struct{}{},
				CVEs: map[string]*model.CVE{
					"cve": {
						ID:              "cve",
						Description:     "CVE in something.",
						PublicationDate: timeParse("2020-02-01T14:30Z"),
						LastUpdate:      timeParse("2020-02-01T14:30Z"),
						CVSS2Vector:     ptr("AV:A/AC:H/Au:S/C:P/I:P/A:C"),
						Configurations:  []*model.Node{},
						Assets:          []*model.Asset{},
						References:      []*model.Reference{},
					},
				},
				CVEVPIndex: map[string]map[string]struct{}{},
			},
		},
		"new-cvss3vector": {
			Memory: &Memory{
				Assets:       map[string]*model.Asset{},
				AssetVPIndex: map[string]map[string]struct{}{},
				CVEs: map[string]*model.CVE{
					"cve": {
						ID:              "cve",
						Description:     "CVE in something.",
						PublicationDate: timeParse("2020-02-01T14:30Z"),
						LastUpdate:      timeParse("2020-02-01T14:30Z"),
						CVSS2Vector:     nil,
						CVSS3Vector:     nil,
						Configurations:  []*model.Node{},
						Assets:          []*model.Asset{},
						References:      []*model.Reference{},
					},
				},
				CVEVPIndex: map[string]map[string]struct{}{},
			},
			Input: UpdateCVEInput{
				ID:             "cve",
				Description:    nil,
				LastUpdate:     nil,
				CVSS2Vector:    nil,
				CVSS3Vector:    ptr("CVSS:3.0/AV:A/AC:H/PR:L/UI:N/S:C/C:L/I:L/A:H"),
				Configurations: nil,
				Assets:         nil,
				References:     nil,
			},
			ExpectedErr: nil,
			ExpectedMemory: &Memory{
				Assets:       map[string]*model.Asset{},
				AssetVPIndex: map[string]map[string]struct{}{},
				CVEs: map[string]*model.CVE{
					"cve": {
						ID:              "cve",
						Description:     "CVE in something.",
						PublicationDate: timeParse("2020-02-01T14:30Z"),
						LastUpdate:      timeParse("2020-02-01T14:30Z"),
						CVSS2Vector:     nil,
						CVSS3Vector:     ptr("CVSS:3.0/AV:A/AC:H/PR:L/UI:N/S:C/C:L/I:L/A:H"),
						Configurations:  []*model.Node{},
						Assets:          []*model.Asset{},
						References:      []*model.Reference{},
					},
				},
				CVEVPIndex: map[string]map[string]struct{}{},
			},
		},
		"new-configurations": {
			Memory: &Memory{
				Assets:       map[string]*model.Asset{},
				AssetVPIndex: map[string]map[string]struct{}{},
				CVEs: map[string]*model.CVE{
					"cve": {
						ID:              "cve",
						Description:     "CVE in something.",
						PublicationDate: timeParse("2020-02-01T14:30Z"),
						LastUpdate:      timeParse("2020-02-01T14:30Z"),
						CVSS2Vector:     nil,
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
									}, {
										Vulnerable:            true,
										CPE23:                 "cpe:2.3:a:fake\\_old:asset:*:*:*:*:*:*:*:*",
										VersionStartIncluding: nil,
										VersionStartExcluding: ptr("3.4.5"),
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
					"fake\\_old:asset": {
						"cve": {},
					},
				},
			},
			Input: UpdateCVEInput{
				ID:          "cve",
				Description: nil,
				LastUpdate:  nil,
				CVSS2Vector: nil,
				CVSS3Vector: nil,
				Configurations: []UpdateCVENodeInput{
					{
						Negate:   ptr(true),
						Operator: "OR",
						Children: []UpdateCVENodeInput{},
						CPEMatches: []UpdateCVENodeCPEMatchInput{
							{
								Vulnerable:            false,
								CPE23:                 "cpe:2.3:a:fake:asset:0.9.6:*:*:*:*:*:*:*",
								VersionStartIncluding: nil,
								VersionStartExcluding: nil,
								VersionEndIncluding:   nil,
								VersionEndExcluding:   nil,
							}, {
								Vulnerable:            false,
								CPE23:                 "cpe:2.3:a:fake\\_new:asset:*:*:*:*:*:*:*:*",
								VersionStartIncluding: nil,
								VersionStartExcluding: nil,
								VersionEndIncluding:   nil,
								VersionEndExcluding:   ptr("1.0.0"),
							},
						},
					},
				},
				Assets:     nil,
				References: nil,
			},
			ExpectedErr: nil,
			ExpectedMemory: &Memory{
				Assets:       map[string]*model.Asset{},
				AssetVPIndex: map[string]map[string]struct{}{},
				CVEs: map[string]*model.CVE{
					"cve": {
						ID:              "cve",
						Description:     "CVE in something.",
						PublicationDate: timeParse("2020-02-01T14:30Z"),
						LastUpdate:      timeParse("2020-02-01T14:30Z"),
						CVSS2Vector:     nil,
						Configurations: []*model.Node{
							{
								Negate:   ptr(true),
								Operator: "OR",
								Children: []*model.Node{},
								CPEMatches: []*model.CPEMatch{
									{
										Vulnerable:            false,
										CPE23:                 "cpe:2.3:a:fake:asset:0.9.6:*:*:*:*:*:*:*",
										VersionStartIncluding: nil,
										VersionStartExcluding: nil,
										VersionEndIncluding:   nil,
										VersionEndExcluding:   nil,
									}, {
										Vulnerable:            false,
										CPE23:                 "cpe:2.3:a:fake\\_new:asset:*:*:*:*:*:*:*:*",
										VersionStartIncluding: nil,
										VersionStartExcluding: nil,
										VersionEndIncluding:   nil,
										VersionEndExcluding:   ptr("1.0.0"),
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
					"fake\\_new:asset": {
						"cve": {},
					},
				},
			},
		},
		"new-assets": {
			Memory: &Memory{
				Assets: map[string]*model.Asset{
					"asset-1": {
						ID:           "asset-1",
						Name:         "Asset 1",
						CPE23:        "cpe:2.3:a:fake:asset:1:*:*:*:*:*:*:*",
						Dependents:   []*model.Asset{},
						Dependencies: []*model.Asset{},
						CVEs: []*model.CVE{
							{
								ID: "cve",
							},
						},
					},
					"asset-2": {
						ID:           "asset-2",
						Name:         "Asset 2",
						CPE23:        "cpe:2.3:a:fake:asset:2:*:*:*:*:*:*:*",
						Dependents:   []*model.Asset{},
						Dependencies: []*model.Asset{},
						CVEs:         []*model.CVE{},
					},
					"asset-3": {
						ID:           "asset-3",
						Name:         "Asset 3",
						CPE23:        "cpe:2.3:a:fake:asset:3:*:*:*:*:*:*:*",
						Dependents:   []*model.Asset{},
						Dependencies: []*model.Asset{},
						CVEs: []*model.CVE{
							{
								ID: "cve",
							},
						},
					},
				},
				AssetVPIndex: map[string]map[string]struct{}{
					"fake:asset": {
						"asset-1": {},
						"asset-2": {},
						"asset-3": {},
					},
				},
				CVEs: map[string]*model.CVE{
					"cve": {
						ID:              "cve",
						Description:     "CVE in something.",
						PublicationDate: timeParse("2020-02-01T14:30Z"),
						LastUpdate:      timeParse("2020-02-01T14:30Z"),
						CVSS2Vector:     nil,
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
								ID: "asset-1",
							}, {
								ID: "asset-3",
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
			Input: UpdateCVEInput{
				ID:             "cve",
				Description:    nil,
				LastUpdate:     nil,
				CVSS2Vector:    nil,
				CVSS3Vector:    nil,
				Configurations: nil,
				Assets: []UpdateCVEAssetInput{
					{
						ID: "asset-2",
					}, {
						ID: "asset-3",
					},
				},
				References: nil,
			},
			ExpectedErr: nil,
			ExpectedMemory: &Memory{
				Assets: map[string]*model.Asset{
					"asset-1": {
						ID:           "asset-1",
						Name:         "Asset 1",
						CPE23:        "cpe:2.3:a:fake:asset:1:*:*:*:*:*:*:*",
						Dependents:   []*model.Asset{},
						Dependencies: []*model.Asset{},
						CVEs:         []*model.CVE{},
					},
					"asset-2": {
						ID:           "asset-2",
						Name:         "Asset 2",
						CPE23:        "cpe:2.3:a:fake:asset:2:*:*:*:*:*:*:*",
						Dependents:   []*model.Asset{},
						Dependencies: []*model.Asset{},
						CVEs: []*model.CVE{
							{
								ID: "cve",
							},
						},
					},
					"asset-3": {
						ID:           "asset-3",
						Name:         "Asset 3",
						CPE23:        "cpe:2.3:a:fake:asset:3:*:*:*:*:*:*:*",
						Dependents:   []*model.Asset{},
						Dependencies: []*model.Asset{},
						CVEs: []*model.CVE{
							{
								ID: "cve",
							},
						},
					},
				},
				AssetVPIndex: map[string]map[string]struct{}{
					"fake:asset": {
						"asset-1": {},
						"asset-2": {},
						"asset-3": {},
					},
				},
				CVEs: map[string]*model.CVE{
					"cve": {
						ID:              "cve",
						Description:     "CVE in something.",
						PublicationDate: timeParse("2020-02-01T14:30Z"),
						LastUpdate:      timeParse("2020-02-01T14:30Z"),
						CVSS2Vector:     nil,
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
								ID: "asset-2",
							}, {
								ID: "asset-3",
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
		},
		"new-references": {
			Memory: &Memory{
				Assets:       map[string]*model.Asset{},
				AssetVPIndex: map[string]map[string]struct{}{},
				CVEs: map[string]*model.CVE{
					"cve": {
						ID:              "cve",
						Description:     "",
						PublicationDate: timeParse("2020-02-01T14:30Z"),
						LastUpdate:      timeParse("2020-02-01T14:30Z"),
						CVSS2Vector:     nil,
						Configurations:  []*model.Node{},
						Assets:          []*model.Asset{},
						References: []*model.Reference{
							{
								URL:       "https://example.com",
								Name:      "Example reference",
								Refsource: "MISC",
								Tags:      []string{"Third Party Advisory"},
							},
						},
					},
				},
				CVEVPIndex: map[string]map[string]struct{}{},
			},
			Input: UpdateCVEInput{
				ID:             "cve",
				Description:    nil,
				LastUpdate:     nil,
				CVSS2Vector:    nil,
				CVSS3Vector:    nil,
				Configurations: nil,
				Assets:         nil,
				References: []UpdateCVEReferencesInput{
					{
						URL:       "https://new-example.com",
						Name:      "Example reference",
						Refsource: "MISC",
						Tags:      []string{"Exploit", "Patch"},
					},
				},
			},
			ExpectedErr: nil,
			ExpectedMemory: &Memory{
				Assets:       map[string]*model.Asset{},
				AssetVPIndex: map[string]map[string]struct{}{},
				CVEs: map[string]*model.CVE{
					"cve": {
						ID:              "cve",
						Description:     "",
						PublicationDate: timeParse("2020-02-01T14:30Z"),
						LastUpdate:      timeParse("2020-02-01T14:30Z"),
						CVSS2Vector:     nil,
						Configurations:  []*model.Node{},
						Assets:          []*model.Asset{},
						References: []*model.Reference{
							{
								URL:       "https://new-example.com",
								Name:      "Example reference",
								Refsource: "MISC",
								Tags:      []string{"Exploit", "Patch"},
							},
						},
					},
				},
				CVEVPIndex: map[string]map[string]struct{}{},
			},
		},
	}

	for testname, tt := range tests {
		t.Run(testname, func(t *testing.T) {
			assert := assert.New(t)

			err := tt.Memory.UpdateCVE(tt.Input)

			assert.Equal(tt.ExpectedErr, err)
			assertEqual(tt.ExpectedMemory, tt.Memory, assert)

			// Check modified input/output does not affect database
			alter(tt.Input)
			assertEqual(tt.ExpectedMemory, tt.Memory, assert)
		})
	}
}

func TestMemoryDeleteCVE(t *testing.T) {
	t.Parallel()

	var tests = map[string]struct {
		Memory         *Memory
		Input          DeleteCVEInput
		ExpectedErr    error
		ExpectedMemory *Memory
	}{
		"unexisting-cve": {
			Memory: &Memory{
				Assets:       map[string]*model.Asset{},
				AssetVPIndex: map[string]map[string]struct{}{},
				CVEs:         map[string]*model.CVE{},
				CVEVPIndex:   map[string]map[string]struct{}{},
			},
			Input: DeleteCVEInput{
				ID: "cve",
			},
			ExpectedErr: &ErrNotExist{
				K: KeyCVE,
				V: "cve",
			},
			ExpectedMemory: &Memory{
				Assets:       map[string]*model.Asset{},
				AssetVPIndex: map[string]map[string]struct{}{},
				CVEs:         map[string]*model.CVE{},
				CVEVPIndex:   map[string]map[string]struct{}{},
			},
		},
		"existing-cve": {
			Memory: &Memory{
				Assets: map[string]*model.Asset{
					"asset": {
						ID:           "asset",
						Name:         "Asset",
						CPE23:        "cpe:2.3:a:fake:asset:*:*:*:*:*:*:*:*",
						Dependents:   []*model.Asset{},
						Dependencies: []*model.Asset{},
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
						Description:     "CVE in something.",
						PublicationDate: timeParse("2020-02-01T14:30Z"),
						LastUpdate:      timeParse("2020-02-01T14:30Z"),
						CVSS2Vector:     nil,
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
			Input: DeleteCVEInput{
				ID: "cve",
			},
			ExpectedErr: nil,
			ExpectedMemory: &Memory{
				Assets: map[string]*model.Asset{
					"asset": {
						ID:           "asset",
						Name:         "Asset",
						CPE23:        "cpe:2.3:a:fake:asset:*:*:*:*:*:*:*:*",
						Dependents:   []*model.Asset{},
						Dependencies: []*model.Asset{},
						CVEs:         []*model.CVE{},
					},
				},
				AssetVPIndex: map[string]map[string]struct{}{
					"fake:asset": {
						"asset": {},
					},
				},
				CVEs:       map[string]*model.CVE{},
				CVEVPIndex: map[string]map[string]struct{}{},
			},
		},
	}

	for testname, tt := range tests {
		t.Run(testname, func(t *testing.T) {
			assert := assert.New(t)

			err := tt.Memory.DeleteCVE(tt.Input)

			assert.Equal(tt.ExpectedErr, err)
			assertEqual(tt.ExpectedMemory, tt.Memory, assert)

			// Check modified input/output does not affect database
			alter(tt.Input)
			assertEqual(tt.ExpectedMemory, tt.Memory, assert)
		})
	}
}

func TestGetAssetCVEs(t *testing.T) {
	t.Parallel()

	var tests = map[string]struct {
		Memory         *Memory
		Asset          *model.Asset
		ExpectedCVEs   []*model.CVE
		ExpectedMemory *Memory
	}{
		"no-cves": {
			Memory: &Memory{
				Assets: map[string]*model.Asset{
					"asset": {
						ID:           "asset",
						Name:         "Asset",
						CPE23:        "cpe:2.3:a:fake:asset:*:*:*:*:*:*:*:*",
						Dependents:   []*model.Asset{},
						Dependencies: []*model.Asset{},
						CVEs:         []*model.CVE{},
					},
				},
				AssetVPIndex: map[string]map[string]struct{}{
					"fake:asset": {
						"asset": {},
					},
				},
				CVEs:       map[string]*model.CVE{},
				CVEVPIndex: map[string]map[string]struct{}{},
			},
			Asset: &model.Asset{
				ID:           "asset",
				Name:         "Asset",
				CPE23:        "cpe:2.3:a:fake:asset:*:*:*:*:*:*:*:*",
				Dependents:   []*model.Asset{},
				Dependencies: []*model.Asset{},
				CVEs:         []*model.CVE{},
			},
			ExpectedCVEs: []*model.CVE{},
			ExpectedMemory: &Memory{
				Assets: map[string]*model.Asset{
					"asset": {
						ID:           "asset",
						Name:         "Asset",
						CPE23:        "cpe:2.3:a:fake:asset:*:*:*:*:*:*:*:*",
						Dependents:   []*model.Asset{},
						Dependencies: []*model.Asset{},
						CVEs:         []*model.CVE{},
					},
				},
				AssetVPIndex: map[string]map[string]struct{}{
					"fake:asset": {
						"asset": {},
					},
				},
				CVEs:       map[string]*model.CVE{},
				CVEVPIndex: map[string]map[string]struct{}{},
			},
		},
		"multiple-cves": {
			Memory: &Memory{
				Assets: map[string]*model.Asset{
					"asset": {
						ID:           "asset",
						Name:         "Asset",
						CPE23:        "cpe:2.3:a:fake:asset:*:*:*:*:*:*:*:*",
						Dependents:   []*model.Asset{},
						Dependencies: []*model.Asset{},
						CVEs: []*model.CVE{
							{
								ID: "cve-1",
							}, {
								ID: "cve-2",
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
					"cve-1": {
						ID:              "cve-1",
						Description:     "CVE example 1",
						PublicationDate: timeParse("2020-01-02T14:00Z"),
						LastUpdate:      timeParse("2020-01-02T14:00Z"),
						CVSS2Vector:     nil,
						Configurations:  []*model.Node{},
						Assets: []*model.Asset{
							{
								ID: "asset",
							},
						},
						References: []*model.Reference{},
					},
					"cve-2": {
						ID:              "cve-2",
						Description:     "CVE example 2",
						PublicationDate: timeParse("2020-01-02T14:00Z"),
						LastUpdate:      timeParse("2020-01-02T14:00Z"),
						CVSS2Vector:     nil,
						Configurations:  []*model.Node{},
						Assets: []*model.Asset{
							{
								ID: "asset",
							},
						},
						References: []*model.Reference{},
					},
				},
				CVEVPIndex: map[string]map[string]struct{}{},
			},
			Asset: &model.Asset{
				ID:           "asset",
				Name:         "Asset",
				CPE23:        "cpe:2.3:a:fake:asset:*:*:*:*:*:*:*:*",
				Dependents:   []*model.Asset{},
				Dependencies: []*model.Asset{},
				CVEs: []*model.CVE{
					{
						ID: "cve-1",
					}, {
						ID: "cve-2",
					},
				},
			},
			ExpectedCVEs: []*model.CVE{
				{
					ID:              "cve-1",
					Description:     "CVE example 1",
					PublicationDate: timeParse("2020-01-02T14:00Z"),
					LastUpdate:      timeParse("2020-01-02T14:00Z"),
					CVSS2Vector:     nil,
					Configurations:  []*model.Node{},
					Assets: []*model.Asset{
						{
							ID: "asset",
						},
					},
					References: []*model.Reference{},
				}, {
					ID:              "cve-2",
					Description:     "CVE example 2",
					PublicationDate: timeParse("2020-01-02T14:00Z"),
					LastUpdate:      timeParse("2020-01-02T14:00Z"),
					CVSS2Vector:     nil,
					Configurations:  []*model.Node{},
					Assets: []*model.Asset{
						{
							ID: "asset",
						},
					},
					References: []*model.Reference{},
				},
			},
			ExpectedMemory: &Memory{
				Assets: map[string]*model.Asset{
					"asset": {
						ID:           "asset",
						Name:         "Asset",
						CPE23:        "cpe:2.3:a:fake:asset:*:*:*:*:*:*:*:*",
						Dependents:   []*model.Asset{},
						Dependencies: []*model.Asset{},
						CVEs: []*model.CVE{
							{
								ID: "cve-1",
							}, {
								ID: "cve-2",
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
					"cve-1": {
						ID:              "cve-1",
						Description:     "CVE example 1",
						PublicationDate: timeParse("2020-01-02T14:00Z"),
						LastUpdate:      timeParse("2020-01-02T14:00Z"),
						CVSS2Vector:     nil,
						Configurations:  []*model.Node{},
						Assets: []*model.Asset{
							{
								ID: "asset",
							},
						},
						References: []*model.Reference{},
					},
					"cve-2": {
						ID:              "cve-2",
						Description:     "CVE example 2",
						PublicationDate: timeParse("2020-01-02T14:00Z"),
						LastUpdate:      timeParse("2020-01-02T14:00Z"),
						CVSS2Vector:     nil,
						Configurations:  []*model.Node{},
						Assets: []*model.Asset{
							{
								ID: "asset",
							},
						},
						References: []*model.Reference{},
					},
				},
				CVEVPIndex: map[string]map[string]struct{}{},
			},
		},
	}

	for testname, tt := range tests {
		t.Run(testname, func(t *testing.T) {
			assert := assert.New(t)

			cves := tt.Memory.GetAssetCVEs(tt.Asset)

			assert.ElementsMatch(tt.ExpectedCVEs, cves)

			// Check modified input/output does not affect database
			alter(tt.Asset)
			alter(cves)
			assertEqual(tt.ExpectedMemory, tt.Memory, assert)
		})
	}
}

func TestGetCVEAssets(t *testing.T) {
	t.Parallel()

	var tests = map[string]struct {
		Memory         *Memory
		CVE            *model.CVE
		ExpectedAssets []*model.Asset
		ExpectedMemory *Memory
	}{
		"no-assets": {
			Memory: &Memory{
				Assets:       map[string]*model.Asset{},
				AssetVPIndex: map[string]map[string]struct{}{},
				CVEs: map[string]*model.CVE{
					"cve": {
						ID:              "cve",
						Description:     "CVE example",
						PublicationDate: timeParse("2020-01-02T14:00Z"),
						LastUpdate:      timeParse("2020-01-02T14:00Z"),
						CVSS2Vector:     nil,
						Configurations:  []*model.Node{},
						Assets:          []*model.Asset{},
					},
				},
				CVEVPIndex: map[string]map[string]struct{}{},
			},
			CVE: &model.CVE{
				ID:              "cve",
				Description:     "CVE example",
				PublicationDate: timeParse("2020-01-02T14:00Z"),
				LastUpdate:      timeParse("2020-01-02T14:00Z"),
				CVSS2Vector:     nil,
				Configurations:  []*model.Node{},
				Assets:          []*model.Asset{},
			},
			ExpectedAssets: []*model.Asset{},
			ExpectedMemory: &Memory{
				Assets:       map[string]*model.Asset{},
				AssetVPIndex: map[string]map[string]struct{}{},
				CVEs: map[string]*model.CVE{
					"cve": {
						ID:              "cve",
						Description:     "CVE example",
						PublicationDate: timeParse("2020-01-02T14:00Z"),
						LastUpdate:      timeParse("2020-01-02T14:00Z"),
						CVSS2Vector:     nil,
						Configurations:  []*model.Node{},
						Assets:          []*model.Asset{},
					},
				},
				CVEVPIndex: map[string]map[string]struct{}{},
			},
		},
		"multiple-assets": {
			Memory: &Memory{
				Assets: map[string]*model.Asset{
					"asset-1": {
						ID:           "asset-1",
						Name:         "Asset 1",
						CPE23:        "cpe:2.3:a:fake:asset:1:*:*:*:*:*:*:*",
						Dependents:   []*model.Asset{},
						Dependencies: []*model.Asset{},
						CVEs: []*model.CVE{
							{
								ID: "cve",
							},
						},
					},
					"asset-2": {
						ID:           "asset-2",
						Name:         "Asset 2",
						CPE23:        "cpe:2.3:a:fake:asset:2:*:*:*:*:*:*:*",
						Dependents:   []*model.Asset{},
						Dependencies: []*model.Asset{},
						CVEs: []*model.CVE{
							{
								ID: "cve",
							},
						},
					},
				},
				AssetVPIndex: map[string]map[string]struct{}{
					"fake:asset": {
						"asset-1": {},
						"asset-2": {},
					},
				},
				CVEs: map[string]*model.CVE{
					"cve": {
						ID:              "cve",
						Description:     "CVE example",
						PublicationDate: timeParse("2020-01-02T14:00Z"),
						LastUpdate:      timeParse("2020-01-02T14:00Z"),
						CVSS2Vector:     nil,
						Configurations:  []*model.Node{},
						Assets: []*model.Asset{
							{
								ID: "asset-1",
							}, {
								ID: "asset-2",
							},
						},
						References: []*model.Reference{},
					},
				},
				CVEVPIndex: map[string]map[string]struct{}{},
			},
			CVE: &model.CVE{
				ID:              "cve",
				Description:     "CVE example",
				PublicationDate: timeParse("2020-01-02T14:00Z"),
				LastUpdate:      timeParse("2020-01-02T14:00Z"),
				CVSS2Vector:     nil,
				Configurations:  []*model.Node{},
				Assets: []*model.Asset{
					{
						ID: "asset-1",
					}, {
						ID: "asset-2",
					},
				},
				References: []*model.Reference{},
			},
			ExpectedAssets: []*model.Asset{
				{
					ID:           "asset-1",
					Name:         "Asset 1",
					CPE23:        "cpe:2.3:a:fake:asset:1:*:*:*:*:*:*:*",
					Dependents:   []*model.Asset{},
					Dependencies: []*model.Asset{},
					CVEs: []*model.CVE{
						{
							ID: "cve",
						},
					},
				}, {
					ID:           "asset-2",
					Name:         "Asset 2",
					CPE23:        "cpe:2.3:a:fake:asset:2:*:*:*:*:*:*:*",
					Dependents:   []*model.Asset{},
					Dependencies: []*model.Asset{},
					CVEs: []*model.CVE{
						{
							ID: "cve",
						},
					},
				},
			},
			ExpectedMemory: &Memory{
				Assets: map[string]*model.Asset{
					"asset-1": {
						ID:           "asset-1",
						Name:         "Asset 1",
						CPE23:        "cpe:2.3:a:fake:asset:1:*:*:*:*:*:*:*",
						Dependents:   []*model.Asset{},
						Dependencies: []*model.Asset{},
						CVEs: []*model.CVE{
							{
								ID: "cve",
							},
						},
					},
					"asset-2": {
						ID:           "asset-2",
						Name:         "Asset 2",
						CPE23:        "cpe:2.3:a:fake:asset:2:*:*:*:*:*:*:*",
						Dependents:   []*model.Asset{},
						Dependencies: []*model.Asset{},
						CVEs: []*model.CVE{
							{
								ID: "cve",
							},
						},
					},
				},
				AssetVPIndex: map[string]map[string]struct{}{
					"fake:asset": {
						"asset-1": {},
						"asset-2": {},
					},
				},
				CVEs: map[string]*model.CVE{
					"cve": {
						ID:              "cve",
						Description:     "CVE example",
						PublicationDate: timeParse("2020-01-02T14:00Z"),
						LastUpdate:      timeParse("2020-01-02T14:00Z"),
						CVSS2Vector:     nil,
						Configurations:  []*model.Node{},
						Assets: []*model.Asset{
							{
								ID: "asset-1",
							}, {
								ID: "asset-2",
							},
						},
						References: []*model.Reference{},
					},
				},
				CVEVPIndex: map[string]map[string]struct{}{},
			},
		},
	}

	for testname, tt := range tests {
		t.Run(testname, func(t *testing.T) {
			assert := assert.New(t)

			assets := tt.Memory.GetCVEAssets(tt.CVE)

			assert.ElementsMatch(tt.ExpectedAssets, assets)

			// Check modified input/output does not affect database
			alter(tt.CVE)
			alter(assets)
			assertEqual(tt.ExpectedMemory, tt.Memory, assert)
		})
	}
}
