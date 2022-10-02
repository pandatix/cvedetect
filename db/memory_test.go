package db_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/pandatix/cvedetect/db"
	"github.com/pandatix/cvedetect/model"
	"github.com/stretchr/testify/assert"
)

var flag = "!!! MODIFIED !!!"

func alter(a any) {
	switch t := a.(type) {
	case *model.Asset:
		t.Name += flag
		t.CPE23 += flag
		for i := 0; i < len(t.CVEs); i++ {
			t.CVEs[i].ID += flag
		}
		for i := 0; i < len(t.Children); i++ {
			t.Children[i].Name += flag
		}

	case *model.CVE:
		t.ID += flag
		for i := 0; i < len(t.Assets); i++ {
			t.Assets[i].Name += flag
		}
		for i := 0; i < len(t.Configurations); i++ {
			t.Configurations[i].Operator += flag
		}
	}
}

func unsem(mem *db.Memory) (dst any) {
	b, _ := json.Marshal(mem)
	_ = json.Unmarshal(b, &dst)
	return
}

func assertEqual(expected, actual *db.Memory, assert *assert.Assertions) {
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
		Memory         *db.Memory
		Input          db.GetAssetInput
		ExpectedAsset  *model.Asset
		ExpectedErr    error
		ExpectedMemory *db.Memory
	}{
		"unexisting-asset": {
			Memory: &db.Memory{
				Assets:       map[string]*model.Asset{},
				CVEs:         map[string]*model.CVE{},
				AssetVPIndex: map[string]map[string]struct{}{},
				CVEVPIndex:   map[string]map[string]struct{}{},
			},
			Input: db.GetAssetInput{
				ID: "asset",
			},
			ExpectedAsset: nil,
			ExpectedErr: &db.ErrNotExist{
				K: db.KeyAsset,
				V: "asset",
			},
			ExpectedMemory: &db.Memory{
				Assets:       map[string]*model.Asset{},
				CVEs:         map[string]*model.CVE{},
				AssetVPIndex: map[string]map[string]struct{}{},
				CVEVPIndex:   map[string]map[string]struct{}{},
			},
		},
		"existing-asset": {
			Memory: &db.Memory{
				Assets: map[string]*model.Asset{
					"asset": {
						ID:       "asset",
						Name:     "Asset",
						CPE23:    "cpe:2.3:a:fake:asset:*:*:*:*:*:*:*:*",
						Parent:   nil,
						Children: []*model.Asset{},
						CVEs:     []*model.CVE{},
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
			Input: db.GetAssetInput{
				ID: "asset",
			},
			ExpectedAsset: &model.Asset{
				ID:       "asset",
				Name:     "Asset",
				CPE23:    "cpe:2.3:a:fake:asset:*:*:*:*:*:*:*:*",
				Parent:   nil,
				Children: []*model.Asset{},
				CVEs:     []*model.CVE{},
			},
			ExpectedErr: nil,
			ExpectedMemory: &db.Memory{
				Assets: map[string]*model.Asset{
					"asset": {
						ID:       "asset",
						Name:     "Asset",
						CPE23:    "cpe:2.3:a:fake:asset:*:*:*:*:*:*:*:*",
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

			// Check return can't be modified
			if asset != nil {
				alter(asset)

				assertEqual(tt.ExpectedMemory, tt.Memory, assert)
			}
		})
	}
}

func TestMemoryQueryAssets(t *testing.T) {
	t.Parallel()

	var tests = map[string]struct {
		Memory         *db.Memory
		Input          db.QueryAssetInput
		ExpectedAssets []*model.Asset
		ExpectedMemory *db.Memory
	}{
		"no-assets": {
			Memory: &db.Memory{
				Assets:       map[string]*model.Asset{},
				AssetVPIndex: map[string]map[string]struct{}{},
				CVEs:         map[string]*model.CVE{},
				CVEVPIndex:   map[string]map[string]struct{}{},
			},
			Input: db.QueryAssetInput{
				VP: nil,
			},
			ExpectedAssets: []*model.Asset{},
			ExpectedMemory: &db.Memory{
				Assets:       map[string]*model.Asset{},
				AssetVPIndex: map[string]map[string]struct{}{},
				CVEs:         map[string]*model.CVE{},
				CVEVPIndex:   map[string]map[string]struct{}{},
			},
		},
		"multiple-assets": {
			Memory: &db.Memory{
				Assets: map[string]*model.Asset{
					"asset-1": {
						ID:       "asset-1",
						Name:     "Asset 1",
						CPE23:    "cpe:2.3:a:fake:asset:1:*:*:*:*:*:*:*",
						Parent:   nil,
						Children: []*model.Asset{},
						CVEs:     []*model.CVE{},
					},
					"asset-2": {
						ID:       "asset-2",
						Name:     "Asset 2",
						CPE23:    "cpe:2.3:a:fake:asset:2:*:*:*:*:*:*:*",
						Parent:   nil,
						Children: []*model.Asset{},
						CVEs:     []*model.CVE{},
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
			Input: db.QueryAssetInput{
				VP: nil,
			},
			ExpectedAssets: []*model.Asset{
				{
					ID:       "asset-1",
					Name:     "Asset 1",
					CPE23:    "cpe:2.3:a:fake:asset:1:*:*:*:*:*:*:*",
					Parent:   nil,
					Children: []*model.Asset{},
					CVEs:     []*model.CVE{},
				}, {
					ID:       "asset-2",
					Name:     "Asset 2",
					CPE23:    "cpe:2.3:a:fake:asset:2:*:*:*:*:*:*:*",
					Parent:   nil,
					Children: []*model.Asset{},
					CVEs:     []*model.CVE{},
				},
			},
			ExpectedMemory: &db.Memory{
				Assets: map[string]*model.Asset{
					"asset-1": {
						ID:       "asset-1",
						Name:     "Asset 1",
						CPE23:    "cpe:2.3:a:fake:asset:1:*:*:*:*:*:*:*",
						Parent:   nil,
						Children: []*model.Asset{},
						CVEs:     []*model.CVE{},
					},
					"asset-2": {
						ID:       "asset-2",
						Name:     "Asset 2",
						CPE23:    "cpe:2.3:a:fake:asset:2:*:*:*:*:*:*:*",
						Parent:   nil,
						Children: []*model.Asset{},
						CVEs:     []*model.CVE{},
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
			Memory: &db.Memory{
				Assets: map[string]*model.Asset{
					"asset-1": {
						ID:       "asset-1",
						Name:     "Asset 1",
						CPE23:    "cpe:2.3:a:fake:asset:1:*:*:*:*:*:*:*",
						Parent:   nil,
						Children: []*model.Asset{},
						CVEs:     []*model.CVE{},
					},
					"asset-2": {
						ID:       "asset-2",
						Name:     "Asset 2",
						CPE23:    "cpe:2.3:a:fake\\_new:asset:2:*:*:*:*:*:*:*",
						Parent:   nil,
						Children: []*model.Asset{},
						CVEs:     []*model.CVE{},
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
			Input: db.QueryAssetInput{
				VP: ptr("fake\\_new:asset"),
			},
			ExpectedAssets: []*model.Asset{
				{
					ID:       "asset-2",
					Name:     "Asset 2",
					CPE23:    "cpe:2.3:a:fake\\_new:asset:2:*:*:*:*:*:*:*",
					Parent:   nil,
					Children: []*model.Asset{},
					CVEs:     []*model.CVE{},
				},
			},
			ExpectedMemory: &db.Memory{
				Assets: map[string]*model.Asset{
					"asset-1": {
						ID:       "asset-1",
						Name:     "Asset 1",
						CPE23:    "cpe:2.3:a:fake:asset:1:*:*:*:*:*:*:*",
						Parent:   nil,
						Children: []*model.Asset{},
						CVEs:     []*model.CVE{},
					},
					"asset-2": {
						ID:       "asset-2",
						Name:     "Asset 2",
						CPE23:    "cpe:2.3:a:fake\\_new:asset:2:*:*:*:*:*:*:*",
						Parent:   nil,
						Children: []*model.Asset{},
						CVEs:     []*model.CVE{},
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
			Memory: &db.Memory{
				Assets: map[string]*model.Asset{
					"asset-1": {
						ID:       "asset-1",
						Name:     "Asset 1",
						CPE23:    "cpe:2.3:a:fake:asset:*:*:*:*:*:*:*:*",
						Parent:   nil,
						Children: []*model.Asset{},
						CVEs:     []*model.CVE{},
					},
					"asset-2": {
						ID:       "asset-2",
						Name:     "Asset 2",
						CPE23:    "cpe:2.3:a:other:asset:*:*:*:*:*:*:*:*",
						Parent:   nil,
						Children: []*model.Asset{},
						CVEs:     []*model.CVE{},
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
			Input: db.QueryAssetInput{
				VP: ptr("*:asset"),
			},
			ExpectedAssets: []*model.Asset{
				{
					ID:       "asset-1",
					Name:     "Asset 1",
					CPE23:    "cpe:2.3:a:fake:asset:*:*:*:*:*:*:*:*",
					Parent:   nil,
					Children: []*model.Asset{},
					CVEs:     []*model.CVE{},
				}, {
					ID:       "asset-2",
					Name:     "Asset 2",
					CPE23:    "cpe:2.3:a:other:asset:*:*:*:*:*:*:*:*",
					Parent:   nil,
					Children: []*model.Asset{},
					CVEs:     []*model.CVE{},
				},
			},
			ExpectedMemory: &db.Memory{
				Assets: map[string]*model.Asset{
					"asset-1": {
						ID:       "asset-1",
						Name:     "Asset 1",
						CPE23:    "cpe:2.3:a:fake:asset:*:*:*:*:*:*:*:*",
						Parent:   nil,
						Children: []*model.Asset{},
						CVEs:     []*model.CVE{},
					},
					"asset-2": {
						ID:       "asset-2",
						Name:     "Asset 2",
						CPE23:    "cpe:2.3:a:other:asset:*:*:*:*:*:*:*:*",
						Parent:   nil,
						Children: []*model.Asset{},
						CVEs:     []*model.CVE{},
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

			// Check return can't be modified
			for i := 0; i < len(assets); i++ {
				alter(assets[i])
			}
			assertEqual(tt.ExpectedMemory, tt.Memory, assert)
		})
	}
}

func TestMemoryAddAsset(t *testing.T) {
	t.Parallel()

	var tests = map[string]struct {
		Memory         *db.Memory
		Input          db.AddAssetInput
		ExpectedErr    error
		ExpectedMemory *db.Memory
	}{
		"asset-exist": {
			Memory: &db.Memory{
				Assets: map[string]*model.Asset{
					"asset": {
						ID:       "asset",
						Name:     "Asset",
						CPE23:    "cpe:2.3:a:fake:asset:*:*:*:*:*:*:*:*",
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
				CVEs:       map[string]*model.CVE{},
				CVEVPIndex: map[string]map[string]struct{}{},
			},
			Input: db.AddAssetInput{
				ID:       "asset",
				Name:     "Asset",
				CPE23:    "cpe:2.3:a:fake:asset:*:*:*:*:*:*:*:*",
				Children: nil,
			},
			ExpectedErr: &db.ErrAlreadyExist{
				K: db.KeyAsset,
				V: "asset",
			},
			ExpectedMemory: &db.Memory{
				Assets: map[string]*model.Asset{
					"asset": {
						ID:       "asset",
						Name:     "Asset",
						CPE23:    "cpe:2.3:a:fake:asset:*:*:*:*:*:*:*:*",
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
				CVEs:       map[string]*model.CVE{},
				CVEVPIndex: map[string]map[string]struct{}{},
			},
		},
		"parent-not-exist": {
			Memory: &db.Memory{
				Assets:       map[string]*model.Asset{},
				AssetVPIndex: map[string]map[string]struct{}{},
				CVEs:         map[string]*model.CVE{},
				CVEVPIndex:   map[string]map[string]struct{}{},
			},
			Input: db.AddAssetInput{
				ID:    "asset",
				Name:  "Asset",
				CPE23: "cpe:2.3:a:fake:asset:*:*:*:*:*:*:*:*",
				Parent: &db.AddAssetParent{
					ID: "unexisting-asset",
				},
				Children: []db.AddAssetChildInput{},
			},
			ExpectedErr: &db.ErrNotExist{
				K: db.KeyAsset,
				V: "unexisting-asset",
			},
			ExpectedMemory: &db.Memory{
				Assets:       map[string]*model.Asset{},
				AssetVPIndex: map[string]map[string]struct{}{},
				CVEs:         map[string]*model.CVE{},
				CVEVPIndex:   map[string]map[string]struct{}{},
			},
		},
		"child-not-exist": {
			Memory: &db.Memory{
				Assets:       map[string]*model.Asset{},
				AssetVPIndex: map[string]map[string]struct{}{},
				CVEs:         map[string]*model.CVE{},
				CVEVPIndex:   map[string]map[string]struct{}{},
			},
			Input: db.AddAssetInput{
				ID:    "asset",
				Name:  "Asset",
				CPE23: "cpe:2.3:a:fake:asset:*:*:*:*:*:*:*:*",
				Children: []db.AddAssetChildInput{
					{
						ID: "unexisting-asset",
					},
				},
			},
			ExpectedErr: &db.ErrNotExist{
				K: db.KeyAsset,
				V: "unexisting-asset",
			},
			ExpectedMemory: &db.Memory{
				Assets:       map[string]*model.Asset{},
				AssetVPIndex: map[string]map[string]struct{}{},
				CVEs:         map[string]*model.CVE{},
				CVEVPIndex:   map[string]map[string]struct{}{},
			},
		},
		"new-asset": {
			Memory: &db.Memory{
				Assets: map[string]*model.Asset{
					"asset-parent": {
						ID:       "asset-parent",
						Name:     "Asset Parent",
						CPE23:    "cpe:2.3:a:fake:asset:*:parent:*:*:*:*:*:*",
						Parent:   nil,
						Children: []*model.Asset{},
						CVEs:     []*model.CVE{},
					},
					"asset-child-1": {
						ID:     "asset-child-1",
						Name:   "Asset Child 1",
						CPE23:  "cpe:2.3:a:fake:asset:1:child:*:*:*:*:*:*",
						Parent: nil,
						Children: []*model.Asset{
							{
								ID: "asset-child-2",
							},
						},
						CVEs: []*model.CVE{},
					},
					"asset-child-2": {
						ID:    "asset-child-2",
						Name:  "Asset Child 2",
						CPE23: "cpe:2.3:a:fake:asset:2:child:*:*:*:*:*:*",
						Parent: &model.Asset{
							ID: "asset-child-1",
						},
						Children: []*model.Asset{},
						CVEs:     []*model.CVE{},
					},
				},
				AssetVPIndex: map[string]map[string]struct{}{
					"fake:asset": {
						"asset-parent":  {},
						"asset-child-1": {},
						"asset-child-2": {},
					},
				},
				CVEs: map[string]*model.CVE{},
			},
			Input: db.AddAssetInput{
				ID:    "asset",
				Name:  "Asset",
				CPE23: "cpe:2.3:a:fake\\_new:asset:*:*:*:*:*:*:*:*",
				Parent: &db.AddAssetParent{
					ID: "asset-parent",
				},
				Children: []db.AddAssetChildInput{
					{
						ID: "asset-child-1",
					}, {
						ID: "asset-child-2",
					},
				},
			},
			ExpectedErr: nil,
			ExpectedMemory: &db.Memory{
				Assets: map[string]*model.Asset{
					"asset-parent": {
						ID:       "asset-parent",
						Name:     "Asset Parent",
						CPE23:    "cpe:2.3:a:fake:asset:*:parent:*:*:*:*:*:*",
						Parent:   nil,
						Children: []*model.Asset{},
						CVEs:     []*model.CVE{},
					},
					"asset": {
						ID:    "asset",
						Name:  "Asset",
						CPE23: "cpe:2.3:a:fake\\_new:asset:*:*:*:*:*:*:*:*",
						Parent: &model.Asset{
							ID: "asset-parent",
						},
						Children: []*model.Asset{
							{
								ID: "asset-child-1",
							}, {
								ID: "asset-child-2",
							},
						},
						CVEs: []*model.CVE{},
					},
					"asset-child-1": {
						ID:    "asset-child-1",
						Name:  "Asset Child 1",
						CPE23: "cpe:2.3:a:fake:asset:1:child:*:*:*:*:*:*",
						Parent: &model.Asset{
							ID: "asset",
						},
						Children: []*model.Asset{},
						CVEs:     []*model.CVE{},
					},
					"asset-child-2": {
						ID:    "asset-child-2",
						Name:  "Asset Child 2",
						CPE23: "cpe:2.3:a:fake:asset:2:child:*:*:*:*:*:*",
						Parent: &model.Asset{
							ID: "asset",
						},
						Children: []*model.Asset{},
						CVEs:     []*model.CVE{},
					},
				},
				AssetVPIndex: map[string]map[string]struct{}{
					"fake:asset": {
						"asset-parent":  {},
						"asset-child-1": {},
						"asset-child-2": {},
					},
					"fake\\_new:asset": {
						"asset": {},
					},
				},
				CVEs: map[string]*model.CVE{},
			},
		},
		"asset-parent-already-exist": {
			Memory: &db.Memory{
				Assets: map[string]*model.Asset{
					"asset-parent": {
						ID:     "asset-parent",
						Name:   "Asset Parent",
						CPE23:  "cpe:2.3:a:fake:asset:*:*:*:*:*:*:*:*",
						Parent: nil,
						Children: []*model.Asset{
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
						Parent: &model.Asset{
							ID: "asset-parent",
						},
						Children: []*model.Asset{},
						CVEs:     []*model.CVE{},
					},
				},
				AssetVPIndex: map[string]map[string]struct{}{
					"fake:asset": {
						"asset":        {},
						"asset-parent": {},
					},
				},
				CVEs:       map[string]*model.CVE{},
				CVEVPIndex: map[string]map[string]struct{}{},
			},
			Input: db.AddAssetInput{
				ID:    "asset-new-parent",
				Name:  "Asset New Parent",
				CPE23: "cpe:2.3:a:fake:asset:*:*:*:*:*:*:*:*",
				Children: []db.AddAssetChildInput{
					{
						ID: "asset",
					},
				},
			},
			ExpectedErr: nil,
			ExpectedMemory: &db.Memory{
				Assets: map[string]*model.Asset{
					"asset-parent": {
						ID:       "asset-parent",
						Name:     "Asset Parent",
						CPE23:    "cpe:2.3:a:fake:asset:*:*:*:*:*:*:*:*",
						Parent:   nil,
						Children: []*model.Asset{},
						CVEs:     []*model.CVE{},
					},
					"asset": {
						ID:    "asset",
						Name:  "Asset",
						CPE23: "cpe:2.3:a:fake:asset:*:*:*:*:*:*:*:*",
						Parent: &model.Asset{
							ID: "asset-new-parent",
						},
						Children: []*model.Asset{},
						CVEs:     []*model.CVE{},
					},
					"asset-new-parent": {
						ID:     "asset-new-parent",
						Name:   "Asset New Parent",
						CPE23:  "cpe:2.3:a:fake:asset:*:*:*:*:*:*:*:*",
						Parent: nil,
						Children: []*model.Asset{
							{
								ID: "asset",
							},
						},
						CVEs: []*model.CVE{},
					},
				},
				AssetVPIndex: map[string]map[string]struct{}{
					"fake:asset": {
						"asset":            {},
						"asset-parent":     {},
						"asset-new-parent": {},
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
		})
	}
}

func TestMemoryUpdateAsset(t *testing.T) {
	t.Parallel()

	var tests = map[string]struct {
		Memory         *db.Memory
		Input          db.UpdateAssetInput
		ExpectedErr    error
		ExpectedMemory *db.Memory
	}{
		"asset-not-exist": {
			Memory: &db.Memory{
				Assets:       map[string]*model.Asset{},
				AssetVPIndex: map[string]map[string]struct{}{},
				CVEs:         map[string]*model.CVE{},
				CVEVPIndex:   map[string]map[string]struct{}{},
			},
			Input: db.UpdateAssetInput{
				ID:       "asset",
				Name:     nil,
				CPE23:    nil,
				Children: nil,
				CVEs:     nil,
			},
			ExpectedErr: &db.ErrNotExist{
				K: db.KeyAsset,
				V: "asset",
			},
			ExpectedMemory: &db.Memory{
				Assets:       map[string]*model.Asset{},
				AssetVPIndex: map[string]map[string]struct{}{},
				CVEs:         map[string]*model.CVE{},
				CVEVPIndex:   map[string]map[string]struct{}{},
			},
		},
		"parent-not-exist": {
			Memory: &db.Memory{
				Assets: map[string]*model.Asset{
					"asset": {
						ID:       "asset",
						Name:     "Asset",
						CPE23:    "cpe:2.3:a:fake:asset:*:*:*:*:*:*:*:*",
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
				CVEs:       map[string]*model.CVE{},
				CVEVPIndex: map[string]map[string]struct{}{},
			},
			Input: db.UpdateAssetInput{
				ID:    "asset",
				Name:  nil,
				CPE23: nil,
				Parent: &db.UpdateAssetParentInput{
					ID: "asset-parent",
				},
				Children: nil,
				CVEs:     nil,
			},
			ExpectedErr: &db.ErrNotExist{
				K: db.KeyAsset,
				V: "asset-parent",
			},
			ExpectedMemory: &db.Memory{
				Assets: map[string]*model.Asset{
					"asset": {
						ID:       "asset",
						Name:     "Asset",
						CPE23:    "cpe:2.3:a:fake:asset:*:*:*:*:*:*:*:*",
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
				CVEs:       map[string]*model.CVE{},
				CVEVPIndex: map[string]map[string]struct{}{},
			},
		},
		"child-not-exist": {
			Memory: &db.Memory{
				Assets: map[string]*model.Asset{
					"asset": {
						ID:       "asset",
						Name:     "Asset",
						CPE23:    "cpe:2.3:a:fake:asset:*:*:*:*:*:*:*:*",
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
				CVEs:       map[string]*model.CVE{},
				CVEVPIndex: map[string]map[string]struct{}{},
			},
			Input: db.UpdateAssetInput{
				ID:    "asset",
				Name:  nil,
				CPE23: nil,
				Children: []db.UpdateAssetChildInput{
					{
						ID: "asset-child",
					},
				},
				CVEs: nil,
			},
			ExpectedErr: &db.ErrNotExist{
				K: db.KeyAsset,
				V: "asset-child",
			},
			ExpectedMemory: &db.Memory{
				Assets: map[string]*model.Asset{
					"asset": {
						ID:       "asset",
						Name:     "Asset",
						CPE23:    "cpe:2.3:a:fake:asset:*:*:*:*:*:*:*:*",
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
				CVEs:       map[string]*model.CVE{},
				CVEVPIndex: map[string]map[string]struct{}{},
			},
		},
		"cve-not-exist": {
			Memory: &db.Memory{
				Assets: map[string]*model.Asset{
					"asset": {
						ID:       "asset",
						Name:     "Asset",
						CPE23:    "cpe:2.3:a:fake:asset:*:*:*:*:*:*:*:*",
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
				CVEs:       map[string]*model.CVE{},
				CVEVPIndex: map[string]map[string]struct{}{},
			},
			Input: db.UpdateAssetInput{
				ID:       "asset",
				Name:     nil,
				CPE23:    nil,
				Children: nil,
				CVEs: []db.UpdateAssetCVEsInput{
					{
						ID: "cve",
					},
				},
			},
			ExpectedErr: &db.ErrNotExist{
				K: db.KeyCVE,
				V: "cve",
			},
			ExpectedMemory: &db.Memory{
				Assets: map[string]*model.Asset{
					"asset": {
						ID:       "asset",
						Name:     "Asset",
						CPE23:    "cpe:2.3:a:fake:asset:*:*:*:*:*:*:*:*",
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
				CVEs:       map[string]*model.CVE{},
				CVEVPIndex: map[string]map[string]struct{}{},
			},
		},
		"new-name": {
			Memory: &db.Memory{
				Assets: map[string]*model.Asset{
					"asset": {
						ID:       "asset",
						Name:     "Asset",
						CPE23:    "cpe:2.3:a:fake:asset:*:*:*:*:*:*:*:*",
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
				CVEs:       map[string]*model.CVE{},
				CVEVPIndex: map[string]map[string]struct{}{},
			},
			Input: db.UpdateAssetInput{
				ID:       "asset",
				Name:     ptr("New Asset"),
				CPE23:    nil,
				Children: nil,
				CVEs:     nil,
			},
			ExpectedErr: nil,
			ExpectedMemory: &db.Memory{
				Assets: map[string]*model.Asset{
					"asset": {
						ID:       "asset",
						Name:     "New Asset",
						CPE23:    "cpe:2.3:a:fake:asset:*:*:*:*:*:*:*:*",
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
				CVEs:       map[string]*model.CVE{},
				CVEVPIndex: map[string]map[string]struct{}{},
			},
		},
		"new-cpe23": {
			Memory: &db.Memory{
				Assets: map[string]*model.Asset{
					"asset": {
						ID:       "asset",
						Name:     "Asset",
						CPE23:    "cpe:2.3:a:fake:asset:1:*:*:*:*:*:*:*",
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
				CVEs:       map[string]*model.CVE{},
				CVEVPIndex: map[string]map[string]struct{}{},
			},
			Input: db.UpdateAssetInput{
				ID:       "asset",
				Name:     nil,
				CPE23:    ptr("cpe:2.3:a:fake\\_other:asset:2:*:*:*:*:*:*:*"),
				Parent:   nil,
				Children: nil,
				CVEs:     nil,
			},
			ExpectedErr: nil,
			ExpectedMemory: &db.Memory{
				Assets: map[string]*model.Asset{
					"asset": {
						ID:       "asset",
						Name:     "Asset",
						CPE23:    "cpe:2.3:a:fake\\_other:asset:2:*:*:*:*:*:*:*",
						Parent:   nil,
						Children: []*model.Asset{},
						CVEs:     []*model.CVE{},
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
		"new-parent": {
			Memory: &db.Memory{
				Assets: map[string]*model.Asset{
					"asset": {
						ID:       "asset",
						Name:     "Asset",
						CPE23:    "cpe:2.3:a:fake:asset:*:*:*:*:*:*:*:*",
						Parent:   nil,
						Children: []*model.Asset{},
						CVEs:     []*model.CVE{},
					},
					"asset-parent": {
						ID:       "asset-parent",
						Name:     "Asset Parent",
						CPE23:    "cpe:2.3:a:fake:asset:*:parent:*:*:*:*:*:*",
						Parent:   nil,
						Children: []*model.Asset{},
						CVEs:     []*model.CVE{},
					},
				},
				AssetVPIndex: map[string]map[string]struct{}{
					"fake:asset": {
						"asset":        {},
						"asset-parent": {},
					},
				},
				CVEs:       map[string]*model.CVE{},
				CVEVPIndex: map[string]map[string]struct{}{},
			},
			Input: db.UpdateAssetInput{
				ID:    "asset",
				Name:  nil,
				CPE23: nil,
				Parent: &db.UpdateAssetParentInput{
					ID: "asset-parent",
				},
				Children: nil,
				CVEs:     nil,
			},
			ExpectedErr: nil,
			ExpectedMemory: &db.Memory{
				Assets: map[string]*model.Asset{
					"asset": {
						ID:    "asset",
						Name:  "Asset",
						CPE23: "cpe:2.3:a:fake:asset:*:*:*:*:*:*:*:*",
						Parent: &model.Asset{
							ID: "asset-parent",
						},
						Children: []*model.Asset{},
						CVEs:     []*model.CVE{},
					},
					"asset-parent": {
						ID:     "asset-parent",
						Name:   "Asset Parent",
						CPE23:  "cpe:2.3:a:fake:asset:*:parent:*:*:*:*:*:*",
						Parent: nil,
						Children: []*model.Asset{
							{
								ID: "asset",
							},
						},
						CVEs: []*model.CVE{},
					},
				},
				AssetVPIndex: map[string]map[string]struct{}{
					"fake:asset": {
						"asset":        {},
						"asset-parent": {},
					},
				},
				CVEs:       map[string]*model.CVE{},
				CVEVPIndex: map[string]map[string]struct{}{},
			},
		},
		"new-parent-already-existing": {
			Memory: &db.Memory{
				Assets: map[string]*model.Asset{
					"asset-parent": {
						ID:     "asset-parent",
						Name:   "Asset Parent",
						CPE23:  "cpe:2.3:a:fake:asset:*:parent:*:*:*:*:*:*",
						Parent: nil,
						Children: []*model.Asset{
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
						Parent: &model.Asset{
							ID: "asset-parent",
						},
						Children: []*model.Asset{},
						CVEs:     []*model.CVE{},
					},
					"asset-future-parent": {
						ID:       "asset-future-parent",
						Name:     "Asset Future Parent",
						CPE23:    "cpe:2.3:a:fake:asset:*:parent:*:*:*:*:*:*",
						Parent:   nil,
						Children: []*model.Asset{},
						CVEs:     []*model.CVE{},
					},
				},
				AssetVPIndex: map[string]map[string]struct{}{
					"fake:asset": {
						"asset":               {},
						"asset-parent":        {},
						"asset-future-parent": {},
					},
				},
				CVEs:       map[string]*model.CVE{},
				CVEVPIndex: map[string]map[string]struct{}{},
			},
			Input: db.UpdateAssetInput{
				ID:    "asset",
				Name:  nil,
				CPE23: nil,
				Parent: &db.UpdateAssetParentInput{
					ID: "asset-future-parent",
				},
				Children: nil,
				CVEs:     nil,
			},
			ExpectedErr: nil,
			ExpectedMemory: &db.Memory{
				Assets: map[string]*model.Asset{
					"asset-parent": {
						ID:       "asset-parent",
						Name:     "Asset Parent",
						CPE23:    "cpe:2.3:a:fake:asset:*:parent:*:*:*:*:*:*",
						Parent:   nil,
						Children: []*model.Asset{},
						CVEs:     []*model.CVE{},
					},
					"asset": {
						ID:    "asset",
						Name:  "Asset",
						CPE23: "cpe:2.3:a:fake:asset:*:*:*:*:*:*:*:*",
						Parent: &model.Asset{
							ID: "asset-future-parent",
						},
						Children: []*model.Asset{},
						CVEs:     []*model.CVE{},
					},
					"asset-future-parent": {
						ID:     "asset-future-parent",
						Name:   "Asset Future Parent",
						CPE23:  "cpe:2.3:a:fake:asset:*:parent:*:*:*:*:*:*",
						Parent: nil,
						Children: []*model.Asset{
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
						"asset-parent":        {},
						"asset-future-parent": {},
					},
				},
				CVEs:       map[string]*model.CVE{},
				CVEVPIndex: map[string]map[string]struct{}{},
			},
		},
		"new-children": {
			Memory: &db.Memory{
				Assets: map[string]*model.Asset{
					"asset": {
						ID:     "asset",
						Name:   "Asset",
						CPE23:  "cpe:2.3:a:fake:asset:*:*:*:*:*:*:*:*",
						Parent: nil,
						Children: []*model.Asset{
							{
								ID: "asset-child-1",
							}, {
								ID: "asset-child-3",
							},
						},
						CVEs: []*model.CVE{},
					},
					"asset-child-1": {
						ID:    "asset-child-1",
						Name:  "Asset Child 1",
						CPE23: "cpe:2.3:a:fake:asset:1:child:*:*:*:*:*:*",
						Parent: &model.Asset{
							ID: "asset",
						},
						Children: []*model.Asset{},
						CVEs:     []*model.CVE{},
					},
					"asset-child-2": {
						ID:       "asset-child-2",
						Name:     "Asset Child 2",
						CPE23:    "cpe:2.3:a:fake:asset:2:child:*:*:*:*:*:*",
						Parent:   nil,
						Children: []*model.Asset{},
						CVEs:     []*model.CVE{},
					},
					"asset-child-3": {
						ID:    "asset-child-3",
						Name:  "Asset Child 3",
						CPE23: "cpe:2.3:a:fake:asset:3:child:*:*:*:*:*:*",
						Parent: &model.Asset{
							ID: "asset",
						},
						Children: []*model.Asset{},
						CVEs:     []*model.CVE{},
					},
				},
				AssetVPIndex: map[string]map[string]struct{}{
					"fake:asset": {
						"asset":         {},
						"asset-child-1": {},
						"asset-child-2": {},
						"asset-child-3": {},
					},
				},
				CVEs:       map[string]*model.CVE{},
				CVEVPIndex: map[string]map[string]struct{}{},
			},
			Input: db.UpdateAssetInput{
				ID:     "asset",
				Name:   nil,
				CPE23:  nil,
				Parent: nil,
				Children: []db.UpdateAssetChildInput{
					{
						ID: "asset-child-2",
					}, {
						ID: "asset-child-3",
					},
				},
				CVEs: nil,
			},
			ExpectedErr: nil,
			ExpectedMemory: &db.Memory{
				Assets: map[string]*model.Asset{
					"asset": {
						ID:     "asset",
						Name:   "Asset",
						CPE23:  "cpe:2.3:a:fake:asset:*:*:*:*:*:*:*:*",
						Parent: nil,
						Children: []*model.Asset{
							{
								ID: "asset-child-2",
							}, {
								ID: "asset-child-3",
							},
						},
						CVEs: []*model.CVE{},
					},
					"asset-child-1": {
						ID:       "asset-child-1",
						Name:     "Asset Child 1",
						CPE23:    "cpe:2.3:a:fake:asset:1:child:*:*:*:*:*:*",
						Parent:   nil,
						Children: []*model.Asset{},
						CVEs:     []*model.CVE{},
					},
					"asset-child-2": {
						ID:    "asset-child-2",
						Name:  "Asset Child 2",
						CPE23: "cpe:2.3:a:fake:asset:2:child:*:*:*:*:*:*",
						Parent: &model.Asset{
							ID: "asset",
						},
						Children: []*model.Asset{},
						CVEs:     []*model.CVE{},
					},
					"asset-child-3": {
						ID:    "asset-child-3",
						Name:  "Asset Child 3",
						CPE23: "cpe:2.3:a:fake:asset:3:child:*:*:*:*:*:*",
						Parent: &model.Asset{
							ID: "asset",
						},
						Children: []*model.Asset{},
						CVEs:     []*model.CVE{},
					},
				},
				AssetVPIndex: map[string]map[string]struct{}{
					"fake:asset": {
						"asset":         {},
						"asset-child-1": {},
						"asset-child-2": {},
						"asset-child-3": {},
					},
				},
				CVEs:       map[string]*model.CVE{},
				CVEVPIndex: map[string]map[string]struct{}{},
			},
		},
		"new-cves": {
			Memory: &db.Memory{
				Assets: map[string]*model.Asset{
					"asset": {
						ID:       "asset",
						Name:     "Asset",
						CPE23:    "cpe:2.3:a:fake:asset:*:*:*:*:*:*:*:*",
						Parent:   nil,
						Children: []*model.Asset{},
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
						CVSS20Vector:    nil,
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
					},
					"cve-2": {
						ID:              "cve-2",
						PublicationDate: timeParse("2020-02-01T14:30Z"),
						LastUpdate:      timeParse("2020-02-01T14:30Z"),
						CVSS20Vector:    nil,
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
						Assets: []*model.Asset{},
					},
					"cve-3": {
						ID:              "cve-3",
						PublicationDate: timeParse("2020-02-17T14:30Z"),
						LastUpdate:      timeParse("2020-02-17T14:30Z"),
						CVSS20Vector:    nil,
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
			Input: db.UpdateAssetInput{
				ID:       "asset",
				Name:     nil,
				CPE23:    nil,
				Parent:   nil,
				Children: nil,
				CVEs: []db.UpdateAssetCVEsInput{
					{
						ID: "cve-2",
					}, {
						ID: "cve-3",
					},
				},
			},
			ExpectedErr: nil,
			ExpectedMemory: &db.Memory{
				Assets: map[string]*model.Asset{
					"asset": {
						ID:       "asset",
						Name:     "Asset",
						CPE23:    "cpe:2.3:a:fake:asset:*:*:*:*:*:*:*:*",
						Parent:   nil,
						Children: []*model.Asset{},
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
						CVSS20Vector:    nil,
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
						Assets: []*model.Asset{},
					},
					"cve-2": {
						ID:              "cve-2",
						PublicationDate: timeParse("2020-02-01T14:30Z"),
						LastUpdate:      timeParse("2020-02-01T14:30Z"),
						CVSS20Vector:    nil,
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
					},
					"cve-3": {
						ID:              "cve-3",
						PublicationDate: timeParse("2020-02-17T14:30Z"),
						LastUpdate:      timeParse("2020-02-17T14:30Z"),
						CVSS20Vector:    nil,
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
		})
	}
}

func TestMemoryDeleteAsset(t *testing.T) {
	t.Parallel()

	var tests = map[string]struct {
		Memory         *db.Memory
		Input          db.DeleteAssetInput
		ExpectedErr    error
		ExpectedMemory *db.Memory
	}{
		"unexisting-asset": {
			Memory: &db.Memory{
				Assets:       map[string]*model.Asset{},
				AssetVPIndex: map[string]map[string]struct{}{},
				CVEs:         map[string]*model.CVE{},
				CVEVPIndex:   map[string]map[string]struct{}{},
			},
			Input: db.DeleteAssetInput{
				ID: "asset",
			},
			ExpectedErr: &db.ErrNotExist{
				K: db.KeyAsset,
				V: "asset",
			},
			ExpectedMemory: &db.Memory{
				Assets:       map[string]*model.Asset{},
				AssetVPIndex: map[string]map[string]struct{}{},
				CVEs:         map[string]*model.CVE{},
				CVEVPIndex:   map[string]map[string]struct{}{},
			},
		},
		"existing-asset": {
			Memory: &db.Memory{
				Assets: map[string]*model.Asset{
					"asset-parent": {
						ID:     "asset-parent",
						Name:   "Asset Parent",
						CPE23:  "cpe:2.3:a:fake:asset:*:parent:*:*:*:*:*:*",
						Parent: nil,
						Children: []*model.Asset{
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
						Parent: &model.Asset{
							ID: "asset-parent",
						},
						Children: []*model.Asset{
							{
								ID: "asset-child",
							},
						},
						CVEs: []*model.CVE{
							{
								ID: "cve",
							},
						},
					},
					"asset-child": {
						ID:    "asset-child",
						Name:  "Asset Child",
						CPE23: "cpe:2.3:a:fake:asset:*:child:*:*:*:*:*:*",
						Parent: &model.Asset{
							ID: "asset",
						},
						Children: []*model.Asset{},
						CVEs:     []*model.CVE{},
					},
				},
				AssetVPIndex: map[string]map[string]struct{}{
					"fake:asset": {
						"asset-parent": {},
						"asset-child":  {},
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
						CVSS20Vector:    nil,
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
			ExpectedErr: nil,
			ExpectedMemory: &db.Memory{
				Assets: map[string]*model.Asset{
					"asset-parent": {
						ID:       "asset-parent",
						Name:     "Asset Parent",
						CPE23:    "cpe:2.3:a:fake:asset:*:parent:*:*:*:*:*:*",
						Parent:   nil,
						Children: []*model.Asset{},
						CVEs:     []*model.CVE{},
					},
					"asset-child": {
						ID:       "asset-child",
						Name:     "Asset Child",
						CPE23:    "cpe:2.3:a:fake:asset:*:child:*:*:*:*:*:*",
						Parent:   nil,
						Children: []*model.Asset{},
						CVEs:     []*model.CVE{},
					},
				},
				AssetVPIndex: map[string]map[string]struct{}{
					"fake:asset": {
						"asset-parent": {},
						"asset-child":  {},
					},
				},
				CVEs: map[string]*model.CVE{
					"cve": {
						ID:              "cve",
						PublicationDate: timeParse("2020-02-01T14:30Z"),
						LastUpdate:      timeParse("2020-02-01T14:30Z"),
						CVSS20Vector:    nil,
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
		})
	}
}

func TestMemoryGetCVE(t *testing.T) {
	t.Parallel()

	var tests = map[string]struct {
		Memory         *db.Memory
		Input          db.GetCVEInput
		ExpectedCVE    *model.CVE
		ExpectedErr    error
		ExpectedMemory *db.Memory
	}{
		"unexisting-cve": {
			Memory: &db.Memory{
				Assets:       map[string]*model.Asset{},
				AssetVPIndex: map[string]map[string]struct{}{},
				CVEs:         map[string]*model.CVE{},
				CVEVPIndex:   map[string]map[string]struct{}{},
			},
			Input: db.GetCVEInput{
				ID: "cve",
			},
			ExpectedCVE: nil,
			ExpectedErr: &db.ErrNotExist{
				K: db.KeyCVE,
				V: "cve",
			},
			ExpectedMemory: &db.Memory{
				Assets:       map[string]*model.Asset{},
				AssetVPIndex: map[string]map[string]struct{}{},
				CVEs:         map[string]*model.CVE{},
				CVEVPIndex:   map[string]map[string]struct{}{},
			},
		},
		"existing-cve": {
			Memory: &db.Memory{
				Assets:       map[string]*model.Asset{},
				AssetVPIndex: map[string]map[string]struct{}{},
				CVEs: map[string]*model.CVE{
					"cve": {
						ID:              "cve",
						Description:     "This is a CVE.",
						PublicationDate: timeParse("2020-02-01T14:30Z"),
						LastUpdate:      timeParse("2020-02-01T14:30Z"),
						CVSS20Vector:    nil,
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
			Input: db.GetCVEInput{
				ID: "cve",
			},
			ExpectedCVE: &model.CVE{
				ID:              "cve",
				Description:     "This is a CVE.",
				PublicationDate: timeParse("2020-02-01T14:30Z"),
				LastUpdate:      timeParse("2020-02-01T14:30Z"),
				CVSS20Vector:    nil,
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
			ExpectedMemory: &db.Memory{
				Assets:       map[string]*model.Asset{},
				AssetVPIndex: map[string]map[string]struct{}{},
				CVEs: map[string]*model.CVE{
					"cve": {
						ID:              "cve",
						Description:     "This is a CVE.",
						PublicationDate: timeParse("2020-02-01T14:30Z"),
						LastUpdate:      timeParse("2020-02-01T14:30Z"),
						CVSS20Vector:    nil,
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

			// Check return can't be modified
			if cve != nil {
				alter(cve)

				assertEqual(tt.ExpectedMemory, tt.Memory, assert)
			}
		})
	}
}

func TestMemoryQueryCVEs(t *testing.T) {
	t.Parallel()

	var tests = map[string]struct {
		Memory         *db.Memory
		Input          db.QueryCVEInput
		ExpectedCVEs   []*model.CVE
		ExpectedMemory *db.Memory
	}{
		"no-cves": {
			Memory: &db.Memory{
				Assets:       map[string]*model.Asset{},
				AssetVPIndex: map[string]map[string]struct{}{},
				CVEs:         map[string]*model.CVE{},
				CVEVPIndex:   map[string]map[string]struct{}{},
			},
			Input: db.QueryCVEInput{
				VP: nil,
			},
			ExpectedCVEs: []*model.CVE{},
			ExpectedMemory: &db.Memory{
				Assets:       map[string]*model.Asset{},
				AssetVPIndex: map[string]map[string]struct{}{},
				CVEs:         map[string]*model.CVE{},
				CVEVPIndex:   map[string]map[string]struct{}{},
			},
		},
		"multiple-cves": {
			Memory: &db.Memory{
				Assets:       map[string]*model.Asset{},
				AssetVPIndex: map[string]map[string]struct{}{},
				CVEs: map[string]*model.CVE{
					"cve-1": {
						ID:              "cve-1",
						PublicationDate: timeParse("2020-02-01T14:30Z"),
						LastUpdate:      timeParse("2020-02-01T14:30Z"),
						CVSS20Vector:    nil,
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
						Assets:     []*model.Asset{},
						References: []*model.Reference{},
					},
					"cve-2": {
						ID:              "cve-2",
						PublicationDate: timeParse("2020-02-01T14:30Z"),
						LastUpdate:      timeParse("2020-02-01T14:30Z"),
						CVSS20Vector:    nil,
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
			Input: db.QueryCVEInput{
				VP: nil,
			},
			ExpectedCVEs: []*model.CVE{
				{
					ID:              "cve-1",
					PublicationDate: timeParse("2020-02-01T14:30Z"),
					LastUpdate:      timeParse("2020-02-01T14:30Z"),
					CVSS20Vector:    nil,
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
					Assets:     []*model.Asset{},
					References: []*model.Reference{},
				}, {
					ID:              "cve-2",
					PublicationDate: timeParse("2020-02-01T14:30Z"),
					LastUpdate:      timeParse("2020-02-01T14:30Z"),
					CVSS20Vector:    nil,
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
					Assets:     []*model.Asset{},
					References: []*model.Reference{},
				},
			},
			ExpectedMemory: &db.Memory{
				Assets:       map[string]*model.Asset{},
				AssetVPIndex: map[string]map[string]struct{}{},
				CVEs: map[string]*model.CVE{
					"cve-1": {
						ID:              "cve-1",
						PublicationDate: timeParse("2020-02-01T14:30Z"),
						LastUpdate:      timeParse("2020-02-01T14:30Z"),
						CVSS20Vector:    nil,
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
						Assets:     []*model.Asset{},
						References: []*model.Reference{},
					},
					"cve-2": {
						ID:              "cve-2",
						PublicationDate: timeParse("2020-02-01T14:30Z"),
						LastUpdate:      timeParse("2020-02-01T14:30Z"),
						CVSS20Vector:    nil,
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
			Memory: &db.Memory{
				Assets:       map[string]*model.Asset{},
				AssetVPIndex: map[string]map[string]struct{}{},
				CVEs: map[string]*model.CVE{
					"cve-1": {
						ID:              "cve-1",
						PublicationDate: timeParse("2020-02-01T14:30Z"),
						LastUpdate:      timeParse("2020-02-01T14:30Z"),
						CVSS20Vector:    nil,
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
						Assets:     []*model.Asset{},
						References: []*model.Reference{},
					},
					"cve-2": {
						ID:              "cve-2",
						PublicationDate: timeParse("2020-02-01T14:30Z"),
						LastUpdate:      timeParse("2020-02-01T14:30Z"),
						CVSS20Vector:    nil,
						CVSS31Vector:    nil,
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
			Input: db.QueryCVEInput{
				VP: ptr("fake:asset"),
			},
			ExpectedCVEs: []*model.CVE{
				{
					ID:              "cve-1",
					PublicationDate: timeParse("2020-02-01T14:30Z"),
					LastUpdate:      timeParse("2020-02-01T14:30Z"),
					CVSS20Vector:    nil,
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
					Assets:     []*model.Asset{},
					References: []*model.Reference{},
				},
			},
			ExpectedMemory: &db.Memory{
				Assets:       map[string]*model.Asset{},
				AssetVPIndex: map[string]map[string]struct{}{},
				CVEs: map[string]*model.CVE{
					"cve-1": {
						ID:              "cve-1",
						PublicationDate: timeParse("2020-02-01T14:30Z"),
						LastUpdate:      timeParse("2020-02-01T14:30Z"),
						CVSS20Vector:    nil,
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
						Assets:     []*model.Asset{},
						References: []*model.Reference{},
					},
					"cve-2": {
						ID:              "cve-2",
						PublicationDate: timeParse("2020-02-01T14:30Z"),
						LastUpdate:      timeParse("2020-02-01T14:30Z"),
						CVSS20Vector:    nil,
						CVSS31Vector:    nil,
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
			Memory: &db.Memory{
				Assets:       map[string]*model.Asset{},
				AssetVPIndex: map[string]map[string]struct{}{},
				CVEs: map[string]*model.CVE{
					"cve-1": {
						ID:              "cve-1",
						Description:     "CVE description 1",
						PublicationDate: timeParse("2020-05-06T09:35Z"),
						LastUpdate:      timeParse("2020-05-06T09:35Z"),
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
			Input: db.QueryCVEInput{
				VP: ptr("*:product"),
			},
			ExpectedCVEs: []*model.CVE{
				{
					ID:              "cve-1",
					Description:     "CVE description 1",
					PublicationDate: timeParse("2020-05-06T09:35Z"),
					LastUpdate:      timeParse("2020-05-06T09:35Z"),
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
			ExpectedMemory: &db.Memory{
				Assets:       map[string]*model.Asset{},
				AssetVPIndex: map[string]map[string]struct{}{},
				CVEs: map[string]*model.CVE{
					"cve-1": {
						ID:              "cve-1",
						Description:     "CVE description 1",
						PublicationDate: timeParse("2020-05-06T09:35Z"),
						LastUpdate:      timeParse("2020-05-06T09:35Z"),
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
		})
	}
}

func TestMemoryAddCVE(t *testing.T) {
	t.Parallel()

	var tests = map[string]struct {
		Memory         *db.Memory
		Input          db.AddCVEInput
		ExpectedErr    error
		ExpectedMemory *db.Memory
	}{
		"cve-exist": {
			Memory: &db.Memory{
				Assets:       map[string]*model.Asset{},
				AssetVPIndex: map[string]map[string]struct{}{},
				CVEs: map[string]*model.CVE{
					"cve": {
						ID:              "cve",
						Description:     "CVE in something.",
						PublicationDate: timeParse("2020-02-01T14:30Z"),
						LastUpdate:      timeParse("2020-02-01T14:30Z"),
						CVSS20Vector:    nil,
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
			Input: db.AddCVEInput{
				ID:              "cve",
				Description:     "CVE in something.",
				PublicationDate: timeParse("2020-02-01T14:30Z"),
				LastUpdate:      timeParse("2020-02-01T14:30Z"),
				CVSS20Vector:    nil,
				CVSS31Vector:    nil,
				Configurations: []db.AddCVENodeInput{
					{
						Negate:   nil,
						Operator: "OR",
						Children: nil,
						CPEMatches: []db.AddCVENodeCPEMatchInput{
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
				References: []db.AddCVEReferenceInput{},
			},
			ExpectedErr: &db.ErrAlreadyExist{
				K: db.KeyCVE,
				V: "cve",
			},
			ExpectedMemory: &db.Memory{
				Assets:       map[string]*model.Asset{},
				AssetVPIndex: map[string]map[string]struct{}{},
				CVEs: map[string]*model.CVE{
					"cve": {
						ID:              "cve",
						Description:     "CVE in something.",
						PublicationDate: timeParse("2020-02-01T14:30Z"),
						LastUpdate:      timeParse("2020-02-01T14:30Z"),
						CVSS20Vector:    nil,
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
			Memory: &db.Memory{
				Assets:       map[string]*model.Asset{},
				AssetVPIndex: map[string]map[string]struct{}{},
				CVEs:         map[string]*model.CVE{},
				CVEVPIndex:   map[string]map[string]struct{}{},
			},
			Input: db.AddCVEInput{
				ID:              "cve",
				Description:     "CVE in something.",
				PublicationDate: timeParse("2020-02-01T14:30Z"),
				LastUpdate:      timeParse("2020-02-01T14:30Z"),
				CVSS20Vector:    ptr("AV:A/AC:H/Au:S/C:P/I:P/A:C"),
				CVSS31Vector:    ptr("CVSS:3.1/AV:A/AC:H/PR:L/UI:N/S:C/C:L/I:L/A:H"),
				Configurations: []db.AddCVENodeInput{
					{
						Negate:   nil,
						Operator: "OR",
						Children: nil,
						CPEMatches: []db.AddCVENodeCPEMatchInput{
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
				References: []db.AddCVEReferenceInput{
					{
						URL:       "https://example.com",
						Name:      "Example reference",
						Refsource: "MISC",
						Tags:      []string{"Patch"},
					},
				},
			},
			ExpectedErr: nil,
			ExpectedMemory: &db.Memory{
				Assets:       map[string]*model.Asset{},
				AssetVPIndex: map[string]map[string]struct{}{},
				CVEs: map[string]*model.CVE{
					"cve": {
						ID:              "cve",
						Description:     "CVE in something.",
						PublicationDate: timeParse("2020-02-01T14:30Z"),
						LastUpdate:      timeParse("2020-02-01T14:30Z"),
						CVSS20Vector:    ptr("AV:A/AC:H/Au:S/C:P/I:P/A:C"),
						CVSS30Vector:    nil,
						CVSS31Vector:    ptr("CVSS:3.1/AV:A/AC:H/PR:L/UI:N/S:C/C:L/I:L/A:H"),
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
		})
	}
}

func TestMemoryUpdateCVE(t *testing.T) {
	t.Parallel()

	var tests = map[string]struct {
		Memory         *db.Memory
		Input          db.UpdateCVEInput
		ExpectedErr    error
		ExpectedMemory *db.Memory
	}{
		"cve-not-exist": {
			Memory: &db.Memory{
				Assets:       map[string]*model.Asset{},
				AssetVPIndex: map[string]map[string]struct{}{},
				CVEs:         map[string]*model.CVE{},
				CVEVPIndex:   map[string]map[string]struct{}{},
			},
			Input: db.UpdateCVEInput{
				ID:             "cve",
				Description:    nil,
				LastUpdate:     nil,
				CVSS20Vector:   nil,
				CVSS31Vector:   nil,
				Configurations: nil,
				Assets:         nil,
			},
			ExpectedErr: &db.ErrNotExist{
				K: db.KeyCVE,
				V: "cve",
			},
			ExpectedMemory: &db.Memory{
				Assets:       map[string]*model.Asset{},
				AssetVPIndex: map[string]map[string]struct{}{},
				CVEs:         map[string]*model.CVE{},
				CVEVPIndex:   map[string]map[string]struct{}{},
			},
		},
		"asset-not-exist": {
			Memory: &db.Memory{
				Assets:       map[string]*model.Asset{},
				AssetVPIndex: map[string]map[string]struct{}{},
				CVEs: map[string]*model.CVE{
					"cve": {
						ID:              "cve",
						Description:     "CVE in something.",
						PublicationDate: timeParse("2020-02-01T14:30Z"),
						LastUpdate:      timeParse("2020-02-01T14:30Z"),
						CVSS20Vector:    ptr("AV:A/AC:H/Au:S/C:P/I:P/A:C"),
						CVSS31Vector:    ptr("CVSS:3.1/AV:A/AC:H/PR:L/UI:N/S:C/C:L/I:L/A:H"),
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
			Input: db.UpdateCVEInput{
				ID:             "cve",
				Description:    nil,
				LastUpdate:     nil,
				CVSS20Vector:   nil,
				CVSS31Vector:   nil,
				Configurations: nil,
				Assets: []db.UpdateCVEAssetInput{
					{
						ID: "asset",
					},
				},
			},
			ExpectedErr: &db.ErrNotExist{
				K: db.KeyAsset,
				V: "asset",
			},
			ExpectedMemory: &db.Memory{
				Assets:       map[string]*model.Asset{},
				AssetVPIndex: map[string]map[string]struct{}{},
				CVEs: map[string]*model.CVE{
					"cve": {
						ID:              "cve",
						Description:     "CVE in something.",
						PublicationDate: timeParse("2020-02-01T14:30Z"),
						LastUpdate:      timeParse("2020-02-01T14:30Z"),
						CVSS20Vector:    ptr("AV:A/AC:H/Au:S/C:P/I:P/A:C"),
						CVSS31Vector:    ptr("CVSS:3.1/AV:A/AC:H/PR:L/UI:N/S:C/C:L/I:L/A:H"),
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
			Memory: &db.Memory{
				Assets:       map[string]*model.Asset{},
				AssetVPIndex: map[string]map[string]struct{}{},
				CVEs: map[string]*model.CVE{
					"cve": {
						ID:              "cve",
						Description:     "CVE in something.",
						PublicationDate: timeParse("2022-02-01T14:30Z"),
						LastUpdate:      timeParse("2022-02-01T14:30Z"),
						CVSS20Vector:    nil,
						CVSS31Vector:    nil,
						Configurations:  []*model.Node{},
						Assets:          []*model.Asset{},
						References:      []*model.Reference{},
					},
				},
				CVEVPIndex: map[string]map[string]struct{}{},
			},
			Input: db.UpdateCVEInput{
				ID:             "cve",
				Description:    ptr("CVE in something, but new."),
				LastUpdate:     nil,
				CVSS20Vector:   nil,
				CVSS31Vector:   nil,
				Configurations: nil,
				Assets:         nil,
				References:     nil,
			},
			ExpectedErr: nil,
			ExpectedMemory: &db.Memory{
				Assets:       map[string]*model.Asset{},
				AssetVPIndex: map[string]map[string]struct{}{},
				CVEs: map[string]*model.CVE{
					"cve": {
						ID:              "cve",
						Description:     "CVE in something, but new.",
						PublicationDate: timeParse("2022-02-01T14:30Z"),
						LastUpdate:      timeParse("2022-02-01T14:30Z"),
						CVSS20Vector:    nil,
						CVSS31Vector:    nil,
						Configurations:  []*model.Node{},
						Assets:          []*model.Asset{},
						References:      []*model.Reference{},
					},
				},
				CVEVPIndex: map[string]map[string]struct{}{},
			},
		},
		"new-lastUpdate": {
			Memory: &db.Memory{
				Assets:       map[string]*model.Asset{},
				AssetVPIndex: map[string]map[string]struct{}{},
				CVEs: map[string]*model.CVE{
					"cve": {
						ID:              "cve",
						Description:     "CVE in something.",
						PublicationDate: timeParse("2020-02-01T14:30Z"),
						LastUpdate:      timeParse("2020-02-01T14:30Z"),
						CVSS20Vector:    nil,
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
			Input: db.UpdateCVEInput{
				ID:             "cve",
				Description:    nil,
				LastUpdate:     ptr(timeParse("2022-02-01T14:30Z")),
				CVSS20Vector:   nil,
				CVSS31Vector:   nil,
				Configurations: nil,
				Assets:         nil,
				References:     nil,
			},
			ExpectedErr: nil,
			ExpectedMemory: &db.Memory{
				Assets:       map[string]*model.Asset{},
				AssetVPIndex: map[string]map[string]struct{}{},
				CVEs: map[string]*model.CVE{
					"cve": {
						ID:              "cve",
						Description:     "CVE in something.",
						PublicationDate: timeParse("2020-02-01T14:30Z"),
						LastUpdate:      timeParse("2022-02-01T14:30Z"),
						CVSS20Vector:    nil,
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
		"new-cvss20vector": {
			Memory: &db.Memory{
				Assets:       map[string]*model.Asset{},
				AssetVPIndex: map[string]map[string]struct{}{},
				CVEs: map[string]*model.CVE{
					"cve": {
						ID:              "cve",
						Description:     "CVE in something.",
						PublicationDate: timeParse("2020-02-01T14:30Z"),
						LastUpdate:      timeParse("2020-02-01T14:30Z"),
						CVSS20Vector:    nil,
						CVSS31Vector:    nil,
						Configurations:  []*model.Node{},
						Assets:          []*model.Asset{},
						References:      []*model.Reference{},
					},
				},
				CVEVPIndex: map[string]map[string]struct{}{},
			},
			Input: db.UpdateCVEInput{
				ID:             "cve",
				Description:    nil,
				LastUpdate:     nil,
				CVSS20Vector:   ptr("AV:A/AC:H/Au:S/C:P/I:P/A:C"),
				CVSS31Vector:   nil,
				Configurations: nil,
				Assets:         nil,
				References:     nil,
			},
			ExpectedErr: nil,
			ExpectedMemory: &db.Memory{
				Assets:       map[string]*model.Asset{},
				AssetVPIndex: map[string]map[string]struct{}{},
				CVEs: map[string]*model.CVE{
					"cve": {
						ID:              "cve",
						Description:     "CVE in something.",
						PublicationDate: timeParse("2020-02-01T14:30Z"),
						LastUpdate:      timeParse("2020-02-01T14:30Z"),
						CVSS20Vector:    ptr("AV:A/AC:H/Au:S/C:P/I:P/A:C"),
						CVSS31Vector:    nil,
						Configurations:  []*model.Node{},
						Assets:          []*model.Asset{},
						References:      []*model.Reference{},
					},
				},
				CVEVPIndex: map[string]map[string]struct{}{},
			},
		},
		"new-cvss30vector": {
			Memory: &db.Memory{
				Assets:       map[string]*model.Asset{},
				AssetVPIndex: map[string]map[string]struct{}{},
				CVEs: map[string]*model.CVE{
					"cve": {
						ID:              "cve",
						Description:     "CVE in something.",
						PublicationDate: timeParse("2020-02-01T14:30Z"),
						LastUpdate:      timeParse("2020-02-01T14:30Z"),
						CVSS20Vector:    nil,
						CVSS30Vector:    nil,
						CVSS31Vector:    nil,
						Configurations:  []*model.Node{},
						Assets:          []*model.Asset{},
						References:      []*model.Reference{},
					},
				},
				CVEVPIndex: map[string]map[string]struct{}{},
			},
			Input: db.UpdateCVEInput{
				ID:             "cve",
				Description:    nil,
				LastUpdate:     nil,
				CVSS20Vector:   nil,
				CVSS30Vector:   ptr("CVSS:3.0/AV:A/AC:H/PR:L/UI:N/S:C/C:L/I:L/A:H"),
				CVSS31Vector:   nil,
				Configurations: nil,
				Assets:         nil,
				References:     nil,
			},
			ExpectedErr: nil,
			ExpectedMemory: &db.Memory{
				Assets:       map[string]*model.Asset{},
				AssetVPIndex: map[string]map[string]struct{}{},
				CVEs: map[string]*model.CVE{
					"cve": {
						ID:              "cve",
						Description:     "CVE in something.",
						PublicationDate: timeParse("2020-02-01T14:30Z"),
						LastUpdate:      timeParse("2020-02-01T14:30Z"),
						CVSS20Vector:    nil,
						CVSS30Vector:    ptr("CVSS:3.0/AV:A/AC:H/PR:L/UI:N/S:C/C:L/I:L/A:H"),
						CVSS31Vector:    nil,
						Configurations:  []*model.Node{},
						Assets:          []*model.Asset{},
						References:      []*model.Reference{},
					},
				},
				CVEVPIndex: map[string]map[string]struct{}{},
			},
		},
		"new-cvss31vector": {
			Memory: &db.Memory{
				Assets:       map[string]*model.Asset{},
				AssetVPIndex: map[string]map[string]struct{}{},
				CVEs: map[string]*model.CVE{
					"cve": {
						ID:              "cve",
						Description:     "CVE in something.",
						PublicationDate: timeParse("2020-02-01T14:30Z"),
						LastUpdate:      timeParse("2020-02-01T14:30Z"),
						CVSS20Vector:    nil,
						CVSS31Vector:    nil,
						Configurations:  []*model.Node{},
						Assets:          []*model.Asset{},
						References:      []*model.Reference{},
					},
				},
				CVEVPIndex: map[string]map[string]struct{}{},
			},
			Input: db.UpdateCVEInput{
				ID:             "cve",
				Description:    nil,
				LastUpdate:     nil,
				CVSS20Vector:   nil,
				CVSS31Vector:   ptr("CVSS:3.1/AV:A/AC:H/PR:L/UI:N/S:C/C:L/I:L/A:H"),
				Configurations: nil,
				Assets:         nil,
				References:     nil,
			},
			ExpectedErr: nil,
			ExpectedMemory: &db.Memory{
				Assets:       map[string]*model.Asset{},
				AssetVPIndex: map[string]map[string]struct{}{},
				CVEs: map[string]*model.CVE{
					"cve": {
						ID:              "cve",
						Description:     "CVE in something.",
						PublicationDate: timeParse("2020-02-01T14:30Z"),
						LastUpdate:      timeParse("2020-02-01T14:30Z"),
						CVSS20Vector:    nil,
						CVSS31Vector:    ptr("CVSS:3.1/AV:A/AC:H/PR:L/UI:N/S:C/C:L/I:L/A:H"),
						Configurations:  []*model.Node{},
						Assets:          []*model.Asset{},
						References:      []*model.Reference{},
					},
				},
				CVEVPIndex: map[string]map[string]struct{}{},
			},
		},
		"new-configurations": {
			Memory: &db.Memory{
				Assets:       map[string]*model.Asset{},
				AssetVPIndex: map[string]map[string]struct{}{},
				CVEs: map[string]*model.CVE{
					"cve": {
						ID:              "cve",
						Description:     "CVE in something.",
						PublicationDate: timeParse("2020-02-01T14:30Z"),
						LastUpdate:      timeParse("2020-02-01T14:30Z"),
						CVSS20Vector:    nil,
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
			Input: db.UpdateCVEInput{
				ID:           "cve",
				Description:  nil,
				LastUpdate:   nil,
				CVSS20Vector: nil,
				CVSS31Vector: nil,
				Configurations: []db.UpdateCVENodeInput{
					{
						Negate:   ptr(true),
						Operator: "OR",
						Children: []db.UpdateCVENodeInput{},
						CPEMatches: []db.UpdateCVENodeCPEMatchInput{
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
			ExpectedMemory: &db.Memory{
				Assets:       map[string]*model.Asset{},
				AssetVPIndex: map[string]map[string]struct{}{},
				CVEs: map[string]*model.CVE{
					"cve": {
						ID:              "cve",
						Description:     "CVE in something.",
						PublicationDate: timeParse("2020-02-01T14:30Z"),
						LastUpdate:      timeParse("2020-02-01T14:30Z"),
						CVSS20Vector:    nil,
						CVSS31Vector:    nil,
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
			Memory: &db.Memory{
				Assets: map[string]*model.Asset{
					"asset-1": {
						ID:       "asset-1",
						Name:     "Asset 1",
						CPE23:    "cpe:2.3:a:fake:asset:1:*:*:*:*:*:*:*",
						Parent:   nil,
						Children: []*model.Asset{},
						CVEs: []*model.CVE{
							{
								ID: "cve",
							},
						},
					},
					"asset-2": {
						ID:       "asset-2",
						Name:     "Asset 2",
						CPE23:    "cpe:2.3:a:fake:asset:2:*:*:*:*:*:*:*",
						Parent:   nil,
						Children: []*model.Asset{},
						CVEs:     []*model.CVE{},
					},
					"asset-3": {
						ID:       "asset-3",
						Name:     "Asset 3",
						CPE23:    "cpe:2.3:a:fake:asset:3:*:*:*:*:*:*:*",
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
						CVSS20Vector:    nil,
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
			Input: db.UpdateCVEInput{
				ID:             "cve",
				Description:    nil,
				LastUpdate:     nil,
				CVSS20Vector:   nil,
				CVSS31Vector:   nil,
				Configurations: nil,
				Assets: []db.UpdateCVEAssetInput{
					{
						ID: "asset-2",
					}, {
						ID: "asset-3",
					},
				},
				References: nil,
			},
			ExpectedErr: nil,
			ExpectedMemory: &db.Memory{
				Assets: map[string]*model.Asset{
					"asset-1": {
						ID:       "asset-1",
						Name:     "Asset 1",
						CPE23:    "cpe:2.3:a:fake:asset:1:*:*:*:*:*:*:*",
						Parent:   nil,
						Children: []*model.Asset{},
						CVEs:     []*model.CVE{},
					},
					"asset-2": {
						ID:       "asset-2",
						Name:     "Asset 2",
						CPE23:    "cpe:2.3:a:fake:asset:2:*:*:*:*:*:*:*",
						Parent:   nil,
						Children: []*model.Asset{},
						CVEs: []*model.CVE{
							{
								ID: "cve",
							},
						},
					},
					"asset-3": {
						ID:       "asset-3",
						Name:     "Asset 3",
						CPE23:    "cpe:2.3:a:fake:asset:3:*:*:*:*:*:*:*",
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
						CVSS20Vector:    nil,
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
			Memory: &db.Memory{
				Assets:       map[string]*model.Asset{},
				AssetVPIndex: map[string]map[string]struct{}{},
				CVEs: map[string]*model.CVE{
					"cve": {
						ID:              "cve",
						Description:     "",
						PublicationDate: timeParse("2020-02-01T14:30Z"),
						LastUpdate:      timeParse("2020-02-01T14:30Z"),
						CVSS20Vector:    nil,
						CVSS31Vector:    nil,
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
			Input: db.UpdateCVEInput{
				ID:             "cve",
				Description:    nil,
				LastUpdate:     nil,
				CVSS20Vector:   nil,
				CVSS31Vector:   nil,
				Configurations: nil,
				Assets:         nil,
				References: []db.UpdateCVEReferencesInput{
					{
						URL:       "https://new-example.com",
						Name:      "Example reference",
						Refsource: "MISC",
						Tags:      []string{"Exploit", "Patch"},
					},
				},
			},
			ExpectedErr: nil,
			ExpectedMemory: &db.Memory{
				Assets:       map[string]*model.Asset{},
				AssetVPIndex: map[string]map[string]struct{}{},
				CVEs: map[string]*model.CVE{
					"cve": {
						ID:              "cve",
						Description:     "",
						PublicationDate: timeParse("2020-02-01T14:30Z"),
						LastUpdate:      timeParse("2020-02-01T14:30Z"),
						CVSS20Vector:    nil,
						CVSS31Vector:    nil,
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
		})
	}
}

func TestMemoryDeleteCVE(t *testing.T) {
	t.Parallel()

	var tests = map[string]struct {
		Memory         *db.Memory
		Input          db.DeleteCVEInput
		ExpectedErr    error
		ExpectedMemory *db.Memory
	}{
		"unexisting-cve": {
			Memory: &db.Memory{
				Assets:       map[string]*model.Asset{},
				AssetVPIndex: map[string]map[string]struct{}{},
				CVEs:         map[string]*model.CVE{},
				CVEVPIndex:   map[string]map[string]struct{}{},
			},
			Input: db.DeleteCVEInput{
				ID: "cve",
			},
			ExpectedErr: &db.ErrNotExist{
				K: db.KeyCVE,
				V: "cve",
			},
			ExpectedMemory: &db.Memory{
				Assets:       map[string]*model.Asset{},
				AssetVPIndex: map[string]map[string]struct{}{},
				CVEs:         map[string]*model.CVE{},
				CVEVPIndex:   map[string]map[string]struct{}{},
			},
		},
		"existing-cve": {
			Memory: &db.Memory{
				Assets: map[string]*model.Asset{
					"asset": {
						ID:       "asset",
						Name:     "Asset",
						CPE23:    "cpe:2.3:a:fake:asset:*:*:*:*:*:*:*:*",
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
						Description:     "CVE in something.",
						PublicationDate: timeParse("2020-02-01T14:30Z"),
						LastUpdate:      timeParse("2020-02-01T14:30Z"),
						CVSS20Vector:    nil,
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
			ExpectedErr: nil,
			ExpectedMemory: &db.Memory{
				Assets: map[string]*model.Asset{
					"asset": {
						ID:       "asset",
						Name:     "Asset",
						CPE23:    "cpe:2.3:a:fake:asset:*:*:*:*:*:*:*:*",
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
		})
	}
}

func TestGetAssetCVEs(t *testing.T) {
	t.Parallel()

	var tests = map[string]struct {
		Memory         *db.Memory
		Asset          *model.Asset
		ExpectedCVEs   []*model.CVE
		ExpectedMemory *db.Memory
	}{
		"no-cves": {
			Memory: &db.Memory{
				Assets: map[string]*model.Asset{
					"asset": {
						ID:       "asset",
						Name:     "Asset",
						CPE23:    "cpe:2.3:a:fake:asset:*:*:*:*:*:*:*:*",
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
				CVEs:       map[string]*model.CVE{},
				CVEVPIndex: map[string]map[string]struct{}{},
			},
			Asset: &model.Asset{
				ID:       "asset",
				Name:     "Asset",
				CPE23:    "cpe:2.3:a:fake:asset:*:*:*:*:*:*:*:*",
				Parent:   nil,
				Children: []*model.Asset{},
				CVEs:     []*model.CVE{},
			},
			ExpectedCVEs: []*model.CVE{},
			ExpectedMemory: &db.Memory{
				Assets: map[string]*model.Asset{
					"asset": {
						ID:       "asset",
						Name:     "Asset",
						CPE23:    "cpe:2.3:a:fake:asset:*:*:*:*:*:*:*:*",
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
				CVEs:       map[string]*model.CVE{},
				CVEVPIndex: map[string]map[string]struct{}{},
			},
		},
		"multiple-cves": {
			Memory: &db.Memory{
				Assets: map[string]*model.Asset{
					"asset": {
						ID:       "asset",
						Name:     "Asset",
						CPE23:    "cpe:2.3:a:fake:asset:*:*:*:*:*:*:*:*",
						Parent:   nil,
						Children: []*model.Asset{},
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
						CVSS20Vector:    nil,
						CVSS31Vector:    nil,
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
						CVSS20Vector:    nil,
						CVSS31Vector:    nil,
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
				ID:       "asset",
				Name:     "Asset",
				CPE23:    "cpe:2.3:a:fake:asset:*:*:*:*:*:*:*:*",
				Parent:   nil,
				Children: []*model.Asset{},
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
					CVSS20Vector:    nil,
					CVSS31Vector:    nil,
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
					CVSS20Vector:    nil,
					CVSS31Vector:    nil,
					Configurations:  []*model.Node{},
					Assets: []*model.Asset{
						{
							ID: "asset",
						},
					},
					References: []*model.Reference{},
				},
			},
			ExpectedMemory: &db.Memory{
				Assets: map[string]*model.Asset{
					"asset": {
						ID:       "asset",
						Name:     "Asset",
						CPE23:    "cpe:2.3:a:fake:asset:*:*:*:*:*:*:*:*",
						Parent:   nil,
						Children: []*model.Asset{},
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
						CVSS20Vector:    nil,
						CVSS31Vector:    nil,
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
						CVSS20Vector:    nil,
						CVSS31Vector:    nil,
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

			// Check return can't be modified
			for i := 0; i < len(cves); i++ {
				alter(cves[i])
			}
			assertEqual(tt.ExpectedMemory, tt.Memory, assert)
		})
	}
}

func TestGetCVEAssets(t *testing.T) {
	t.Parallel()

	var tests = map[string]struct {
		Memory         *db.Memory
		CVE            *model.CVE
		ExpectedAssets []*model.Asset
		ExpectedMemory *db.Memory
	}{
		"no-assets": {
			Memory: &db.Memory{
				Assets:       map[string]*model.Asset{},
				AssetVPIndex: map[string]map[string]struct{}{},
				CVEs: map[string]*model.CVE{
					"cve": {
						ID:              "cve",
						Description:     "CVE example",
						PublicationDate: timeParse("2020-01-02T14:00Z"),
						LastUpdate:      timeParse("2020-01-02T14:00Z"),
						CVSS20Vector:    nil,
						CVSS31Vector:    nil,
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
				CVSS20Vector:    nil,
				CVSS31Vector:    nil,
				Configurations:  []*model.Node{},
				Assets:          []*model.Asset{},
			},
			ExpectedAssets: []*model.Asset{},
			ExpectedMemory: &db.Memory{
				Assets:       map[string]*model.Asset{},
				AssetVPIndex: map[string]map[string]struct{}{},
				CVEs: map[string]*model.CVE{
					"cve": {
						ID:              "cve",
						Description:     "CVE example",
						PublicationDate: timeParse("2020-01-02T14:00Z"),
						LastUpdate:      timeParse("2020-01-02T14:00Z"),
						CVSS20Vector:    nil,
						CVSS31Vector:    nil,
						Configurations:  []*model.Node{},
						Assets:          []*model.Asset{},
					},
				},
				CVEVPIndex: map[string]map[string]struct{}{},
			},
		},
		"multiple-assets": {
			Memory: &db.Memory{
				Assets: map[string]*model.Asset{
					"asset-1": {
						ID:       "asset-1",
						Name:     "Asset 1",
						CPE23:    "cpe:2.3:a:fake:asset:1:*:*:*:*:*:*:*",
						Parent:   nil,
						Children: []*model.Asset{},
						CVEs: []*model.CVE{
							{
								ID: "cve",
							},
						},
					},
					"asset-2": {
						ID:       "asset-2",
						Name:     "Asset 2",
						CPE23:    "cpe:2.3:a:fake:asset:2:*:*:*:*:*:*:*",
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
						CVSS20Vector:    nil,
						CVSS31Vector:    nil,
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
				CVSS20Vector:    nil,
				CVSS31Vector:    nil,
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
					ID:       "asset-1",
					Name:     "Asset 1",
					CPE23:    "cpe:2.3:a:fake:asset:1:*:*:*:*:*:*:*",
					Parent:   nil,
					Children: []*model.Asset{},
					CVEs: []*model.CVE{
						{
							ID: "cve",
						},
					},
				}, {
					ID:       "asset-2",
					Name:     "Asset 2",
					CPE23:    "cpe:2.3:a:fake:asset:2:*:*:*:*:*:*:*",
					Parent:   nil,
					Children: []*model.Asset{},
					CVEs: []*model.CVE{
						{
							ID: "cve",
						},
					},
				},
			},
			ExpectedMemory: &db.Memory{
				Assets: map[string]*model.Asset{
					"asset-1": {
						ID:       "asset-1",
						Name:     "Asset 1",
						CPE23:    "cpe:2.3:a:fake:asset:1:*:*:*:*:*:*:*",
						Parent:   nil,
						Children: []*model.Asset{},
						CVEs: []*model.CVE{
							{
								ID: "cve",
							},
						},
					},
					"asset-2": {
						ID:       "asset-2",
						Name:     "Asset 2",
						CPE23:    "cpe:2.3:a:fake:asset:2:*:*:*:*:*:*:*",
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
						CVSS20Vector:    nil,
						CVSS31Vector:    nil,
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

			// Check return can't be modified
			for i := 0; i < len(assets); i++ {
				alter(assets[i])
			}
			assertEqual(tt.ExpectedMemory, tt.Memory, assert)
		})
	}
}
