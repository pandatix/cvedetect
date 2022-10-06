package utils_test

import (
	"testing"

	"github.com/pandatix/cvedetect/api/utils"
	"github.com/pandatix/cvedetect/model"
	"github.com/stretchr/testify/assert"
)

func TestCheckMultigraph(t *testing.T) {
	t.Parallel()

	var tests = map[string]struct {
		Asset       *model.Asset
		ExpectedErr error
	}{
		"graph": {
			Asset: &model.Asset{
				ID:    "asset",
				Name:  "Asset",
				CPE23: "cpe:2.3:a:fake:asset:*:*:*:*:*:*:*:*",
				Parents: []*model.Asset{
					{
						ID: "parent-asset",
					},
				},
				Children: []*model.Asset{
					{
						ID: "children-asset",
					},
				},
				CVEs: []*model.CVE{},
			},
			ExpectedErr: nil,
		},
		"multigraph-parent": {
			Asset: &model.Asset{
				ID:    "asset",
				Name:  "Asset",
				CPE23: "cpe:2.3:a:fake:asset:*:*:*:*:*:*:*:*",
				Parents: []*model.Asset{
					{
						ID: "parent-asset",
					}, {
						ID: "parent-asset",
					},
				},
				Children: []*model.Asset{},
				CVEs:     []*model.CVE{},
			},
			ExpectedErr: utils.ErrMultigraph,
		},
		"multigraph-children": {
			Asset: &model.Asset{
				ID:      "asset",
				Name:    "Asset",
				CPE23:   "cpe:2.3:a:fake:asset:*:*:*:*:*:*:*:*",
				Parents: []*model.Asset{},
				Children: []*model.Asset{
					{
						ID: "children-asset",
					}, {
						ID: "children-asset",
					},
				},
				CVEs: []*model.CVE{},
			},
			ExpectedErr: utils.ErrMultigraph,
		},
	}

	for testname, tt := range tests {
		t.Run(testname, func(t *testing.T) {
			assert := assert.New(t)

			err := utils.CheckMultigraph(tt.Asset)

			assert.Equal(tt.ExpectedErr, err)
		})
	}
}
