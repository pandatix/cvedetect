package query

import (
	"github.com/pandatix/cvedetect/db"
	"github.com/pandatix/cvedetect/model"
)

func GetAsset(mem *db.Memory, input db.GetAssetInput) (*model.Asset, error) {
	return mem.GetAsset(input)
}

func QueryAssets(mem *db.Memory, input db.QueryAssetInput) ([]*model.Asset, error) {
	return mem.QueryAssets(input), nil
}
