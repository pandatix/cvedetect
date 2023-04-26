package utils

import (
	"errors"

	"github.com/pandatix/cvedetect/model"
)

var (
	ErrMultigraph = errors.New("multigraph detected")
)

// CheckMultigraph returns ErrMultigraph if the given fake
// asset should create a multigraph, whether it is in it's dependents
// or dependencies.
// "fake" means it is the result of an asset built for this
// check as it could be saved in the in-memory database, but that
// is not yet saved in it.
func CheckMultigraph(asset *model.Asset) error {
	// In the case of an AddAsset mutation:
	// - a multigraph can happen when a new asset claims a dependent
	//   or a dependency multiple times.
	// In the case of an UpdateAsset mutation:
	// - a multgraph can happen when an existing asset that has a
	//   link with another asset tries to have more
	// - a multigraph can happen when an existing asset that has no
	//   link with another asset tries to have many
	//
	// Those scenarios share in common that the mutations will make
	// the asset having multiple links with another.
	// The strategy of this checker is redundant for dependents and
	// dependencies, given the fake asset:
	// - create an empty list for known assets
	// - for each related assets, if it is already referenced in the list
	//   then return the error, else reference it
	if err := chkMultigraph(asset.Dependents); err != nil {
		return err
	}
	return chkMultigraph(asset.Dependencies)
}

func chkMultigraph(assets []*model.Asset) error {
	knowns := map[string]struct{}{}
	for _, asset := range assets {
		if _, ok := knowns[asset.ID]; ok {
			return ErrMultigraph
		}
		knowns[asset.ID] = struct{}{}
	}
	return nil
}
