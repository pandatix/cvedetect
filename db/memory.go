package db

import (
	"encoding/json"
	"sync"

	"github.com/knqyf263/go-cpe/matching"
	"github.com/knqyf263/go-cpe/naming"
	"github.com/pandatix/cvedetect/internal"
	"github.com/pandatix/cvedetect/model"
)

// Memory holds the in-memory graph database, powering the whole tool.
// It only achieve what a standard graph database is expected to do :
// checks for consistency of (un)existing objects, but no more.
// Cycles, multigraphs...etc. are handled by the business layer.
//
// Input and output objects are hardened by a copy of values to block
// the possibility of modifying the outside data affecting the saved data,
// so a Memory instance can behave as an outside component (sealed from
// the current application).
type Memory struct {
	mx sync.RWMutex

	// Assets indexes *model.Asset on to the ID
	Assets map[string]*model.Asset
	// AssetVPIndex indexes *model.Asset on the vendor:product
	// couple of the CPEs.
	// Second map indexes by the Asset's ID.
	AssetVPIndex map[string]map[string]struct{}

	// CVEs indexes *model.CVE on to the ID
	CVEs map[string]*model.CVE
	// CVEVPIndex indexes *model.CVE on the vendor:product couple
	// of the CPEs in its configurations.
	// Second map indexes by the CVE's ID.
	CVEVPIndex map[string]map[string]struct{}
}

func NewMemory() *Memory {
	return &Memory{
		mx:           sync.RWMutex{},
		Assets:       map[string]*model.Asset{},
		AssetVPIndex: map[string]map[string]struct{}{},
		CVEs:         map[string]*model.CVE{},
		CVEVPIndex:   map[string]map[string]struct{}{},
	}
}

func (mem *Memory) GetAsset(input GetAssetInput) (*model.Asset, error) {
	mem.mx.RLock()
	defer mem.mx.RUnlock()

	// Check for consistency
	asset, ok := mem.Assets[input.ID]
	if !ok {
		return nil, &ErrNotExist{
			K: KeyAsset,
			V: input.ID,
		}
	}

	return copyAsset(asset), nil
}

func (mem *Memory) QueryAssets(input QueryAssetInput) []*model.Asset {
	mem.mx.RLock()
	defer mem.mx.RUnlock()

	// Select assets to query
	var mp map[string]*model.Asset = mem.Assets
	if input.VP != nil {
		v, p := splitVP(*input.VP)
		if containsWildcard(v) || containsWildcard(p) {
			// Select using subset
			inWFN, _ := naming.UnbindFS("cpe:2.3:a:" + *input.VP + "*:*:*:*:*:*:*:*")
			mp = map[string]*model.Asset{}
			for vp, assetsIDs := range mem.AssetVPIndex {
				// XXX workaround as matching.CompareStrings are is not directly accessible.
				assetWFN, _ := naming.UnbindFS("cpe:2.3:a:" + vp + "*:*:*:*:*:*:*:*")
				if matching.IsSuperset(inWFN, assetWFN) {
					for assetID := range assetsIDs {
						mp[assetID] = mem.Assets[assetID]
					}
				}
			}
		} else {
			// Select directly
			mp = make(map[string]*model.Asset, len(mem.AssetVPIndex[*input.VP]))
			for assetID := range mem.AssetVPIndex[*input.VP] {
				mp[assetID] = mem.Assets[assetID]
			}
		}
	}

	assets := make([]*model.Asset, len(mp))
	i := 0
	for _, asset := range mp {
		assets[i] = copyAsset(asset)
		i++
	}
	return assets
}

func (mem *Memory) AddAsset(input AddAssetInput) error {
	mem.mx.Lock()
	defer mem.mx.Unlock()

	// Check for consistency
	// => Component
	if _, ok := mem.Assets[input.ID]; ok {
		return &ErrAlreadyExist{
			K: KeyAsset,
			V: input.ID,
		}
	}
	// => Parents
	for _, parent := range input.Parents {
		if _, ok := mem.Assets[parent.ID]; !ok {
			return &ErrNotExist{
				K: KeyAsset,
				V: parent.ID,
			}
		}
	}
	// => Children
	for _, child := range input.Children {
		if _, ok := mem.Assets[child.ID]; !ok {
			return &ErrNotExist{
				K: KeyAsset,
				V: child.ID,
			}
		}
	}

	// TODO Check if will create a cycle

	// Save data
	// => Assets map
	children := make([]*model.Asset, len(input.Children))
	for i, child := range input.Children {
		children[i] = &model.Asset{
			ID: child.ID,
		}

		// Set child's parent relation
		child := mem.Assets[child.ID]
		child.Parents = append(child.Parents, &model.Asset{
			ID: input.ID,
		})
	}
	parents := make([]*model.Asset, len(input.Parents))
	for i, parent := range input.Parents {
		parents[i] = &model.Asset{
			ID: parent.ID,
		}

		// Set parent's child relation
		parent := mem.Assets[parent.ID]
		parent.Children = append(parent.Children, &model.Asset{
			ID: input.ID,
		})
	}
	mem.Assets[input.ID] = &model.Asset{
		ID:       input.ID,
		Name:     input.Name,
		CPE23:    input.CPE23,
		Parents:  parents,
		Children: children,
		CVEs:     []*model.CVE{},
	}
	// => Index map
	vp := internal.GetVP(input.CPE23)
	if _, ok := mem.AssetVPIndex[vp]; !ok {
		mem.AssetVPIndex[vp] = map[string]struct{}{}
	}
	mem.AssetVPIndex[vp][input.ID] = struct{}{}

	return nil
}

func (mem *Memory) UpdateAsset(input UpdateAssetInput) error {
	mem.mx.Lock()
	defer mem.mx.Unlock()

	// Check for consistency
	// => Asset
	asset, ok := mem.Assets[input.ID]
	if !ok {
		return &ErrNotExist{
			K: KeyAsset,
			V: input.ID,
		}
	}
	// => Parent
	for _, parent := range input.Parents {
		if _, ok := mem.Assets[parent.ID]; !ok {
			return &ErrNotExist{
				K: KeyAsset,
				V: parent.ID,
			}
		}
	}
	// => Children
	for _, child := range input.Children {
		if _, ok := mem.Assets[child.ID]; !ok {
			return &ErrNotExist{
				K: KeyAsset,
				V: child.ID,
			}
		}
	}
	// => CVE
	for _, cve := range input.CVEs {
		if _, ok := mem.CVEs[cve.ID]; !ok {
			return &ErrNotExist{
				K: KeyCVE,
				V: cve.ID,
			}
		}
	}

	// TODO Check if will create a cycle

	// Save data
	// => Name
	if input.Name != nil {
		asset.Name = *input.Name
	}
	// => CPE23
	if input.CPE23 != nil {
		// Update index
		vpOld := internal.GetVP(asset.CPE23)
		vpNew := internal.GetVP(*input.CPE23)
		if vpNew != vpOld {
			// Delete old index
			delete(mem.AssetVPIndex[vpOld], asset.ID)
			if len(mem.AssetVPIndex[vpOld]) == 0 {
				delete(mem.AssetVPIndex, vpOld)
			}

			// Add new index
			if _, ok := mem.AssetVPIndex[vpNew]; !ok {
				mem.AssetVPIndex[vpNew] = map[string]struct{}{}
			}
			mem.AssetVPIndex[vpNew][asset.ID] = struct{}{}
		}
		asset.CPE23 = *input.CPE23
	}
	// => Parents
	if input.Parents != nil {
		newParents := make([]*model.Asset, len(input.Parents))
		for i, parent := range input.Parents {
			newParents[i] = &model.Asset{
				ID: parent.ID,
			}
		}
		// Update parents
		for _, parent := range asset.Parents {
			remains := false
			for _, inputParent := range input.Parents {
				if parent.ID == inputParent.ID {
					remains = true
					break
				}
			}
			if !remains {
				// Delete link
				parent := mem.Assets[parent.ID]
				parent.Children = removeAsset(parent.Children, asset)
			}
		}
		for _, inputParent := range input.Parents {
			found := false
			for _, parent := range asset.Parents {
				if inputParent.ID == parent.ID {
					found = true
					break
				}
			}
			if !found {
				// Create link
				parent := mem.Assets[inputParent.ID]
				parent.Children = append(parent.Children, &model.Asset{
					ID: asset.ID,
				})
			}
		}
		asset.Parents = newParents
	}
	// => Children
	if input.Children != nil {
		newChildren := make([]*model.Asset, len(input.Children))
		for i, child := range input.Children {
			newChildren[i] = &model.Asset{
				ID: child.ID,
			}
		}
		// Update children
		for _, child := range asset.Children {
			remains := false
			for _, inputChild := range input.Children {
				if child.ID == inputChild.ID {
					remains = true
					break
				}
			}
			if !remains {
				// Delete link
				child := mem.Assets[child.ID]
				child.Parents = removeAsset(child.Parents, asset)
			}
		}
		for _, inputChild := range input.Children {
			found := false
			for _, child := range asset.Children {
				if inputChild.ID == child.ID {
					found = true
					break
				}
			}
			if !found {
				// Create link
				child := mem.Assets[inputChild.ID]
				child.Parents = append(child.Parents, &model.Asset{
					ID: asset.ID,
				})
			}
		}
		asset.Children = newChildren
	}
	// => CVEs
	if input.CVEs != nil {
		newCVES := make([]*model.CVE, len(input.CVEs))
		for i, cve := range input.CVEs {
			newCVES[i] = &model.CVE{
				ID: cve.ID,
			}
		}
		// Update links
		for _, cve := range asset.CVEs {
			remains := false
			for _, inputCVE := range input.CVEs {
				if cve.ID == inputCVE.ID {
					remains = true
					break
				}
			}
			if !remains {
				// Delete link
				cve := mem.CVEs[cve.ID]
				cve.Assets = removeAsset(cve.Assets, asset)
			}
		}
		for _, inputCVE := range input.CVEs {
			found := false
			for _, cve := range asset.CVEs {
				if inputCVE.ID == cve.ID {
					found = true
					break
				}
			}
			if !found {
				// Add link
				cve := mem.CVEs[inputCVE.ID]
				cve.Assets = append(cve.Assets, &model.Asset{
					ID: asset.ID,
				})
			}
		}
		asset.CVEs = newCVES
	}

	return nil
}

func (mem *Memory) DeleteAsset(input DeleteAssetInput) error {
	mem.mx.Lock()
	defer mem.mx.Unlock()

	// Check for consistency
	asset, ok := mem.Assets[input.ID]
	if !ok {
		return &ErrNotExist{
			K: KeyAsset,
			V: input.ID,
		}
	}

	// Save data
	// => Parent
	for _, parent := range asset.Parents {
		parent := mem.Assets[parent.ID]
		parent.Children = removeAsset(parent.Children, asset)
	}
	// => Children
	for _, child := range asset.Children {
		child := mem.Assets[child.ID]
		child.Parents = removeAsset(child.Parents, asset)
	}
	// => CVEs
	for _, assetCve := range asset.CVEs {
		cve := mem.CVEs[assetCve.ID]
		cve.Assets = removeAsset(cve.Assets, asset)
	}
	// => Index
	vp := internal.GetVP(asset.CPE23)
	delete(mem.AssetVPIndex[vp], asset.ID)
	if len(mem.AssetVPIndex[vp]) == 0 {
		delete(mem.AssetVPIndex, vp)
	}
	delete(mem.Assets, asset.ID)

	return nil
}

func (mem *Memory) GetCVE(input GetCVEInput) (*model.CVE, error) {
	mem.mx.RLock()
	defer mem.mx.RUnlock()

	// Check for consistency
	cve, ok := mem.CVEs[input.ID]
	if !ok {
		return nil, &ErrNotExist{
			K: KeyCVE,
			V: input.ID,
		}
	}
	return copyCVE(cve), nil
}

func (mem *Memory) QueryCVEs(input QueryCVEInput) []*model.CVE {
	mem.mx.RLock()
	defer mem.mx.RUnlock()

	var mp map[string]*model.CVE = mem.CVEs
	if input.VP != nil {
		v, p := splitVP(*input.VP)
		if containsWildcard(v) || containsWildcard(p) {
			// Select using subset
			inWFN, _ := naming.UnbindFS("cpe:2.3:a:" + *input.VP + "*:*:*:*:*:*:*:*")
			mp = map[string]*model.CVE{}
			for vp, cvesIDs := range mem.CVEVPIndex {
				// XXX workaround as matching.assetare is not directly accessible.
				assetWFN, _ := naming.UnbindFS("cpe:2.3:a:" + vp + "*:*:*:*:*:*:*:*")
				if matching.IsSuperset(inWFN, assetWFN) {
					for cveID := range cvesIDs {
						mp[cveID] = mem.CVEs[cveID]
					}
				}
			}
		} else {
			// Select directly
			mp = make(map[string]*model.CVE, len(mem.CVEVPIndex[*input.VP]))
			for cveID := range mem.CVEVPIndex[*input.VP] {
				mp[cveID] = mem.CVEs[cveID]
			}
		}
	}

	cves := make([]*model.CVE, len(mp))
	i := 0
	for _, cve := range mp {
		cves[i] = copyCVE(cve)
		i++
	}
	return cves
}

func (mem *Memory) AddCVE(input AddCVEInput) error {
	mem.mx.Lock()
	defer mem.mx.Unlock()

	// Check for consistency
	if _, ok := mem.CVEs[input.ID]; ok {
		return &ErrAlreadyExist{
			K: KeyCVE,
			V: input.ID,
		}
	}

	// Save data
	// => CVE
	configurations := make([]*model.Node, len(input.Configurations))
	for i, conf := range input.Configurations {
		configurations[i] = loadInputConf(conf)
	}
	references := make([]*model.Reference, len(input.References))
	for i, ref := range input.References {
		tags := make([]string, len(ref.Tags))
		copy(tags, ref.Tags)
		references[i] = &model.Reference{
			URL:       ref.URL,
			Name:      ref.Name,
			Refsource: ref.Refsource,
			Tags:      tags,
		}
	}
	mem.CVEs[input.ID] = &model.CVE{
		ID:              input.ID,
		Description:     input.Description,
		PublicationDate: input.PublicationDate,
		LastUpdate:      input.LastUpdate,
		CVSS2Vector:     cpPtrValue(input.CVSS2Vector),
		CVSS3Vector:     cpPtrValue(input.CVSS3Vector),
		Configurations:  configurations,
		Assets:          []*model.Asset{},
		References:      references,
	}
	// => Index
	cpes23 := getAllCPEs23(configurations)
	for _, cpe23 := range cpes23 {
		vp := internal.GetVP(cpe23)
		if _, ok := mem.CVEVPIndex[vp]; !ok {
			mem.CVEVPIndex[vp] = map[string]struct{}{}
		}
		mem.CVEVPIndex[vp][input.ID] = struct{}{}
	}

	return nil
}

func (mem *Memory) UpdateCVE(input UpdateCVEInput) error {
	mem.mx.Lock()
	defer mem.mx.Unlock()

	// Check for consistency
	// => CVE
	cve, ok := mem.CVEs[input.ID]
	if !ok {
		return &ErrNotExist{
			K: KeyCVE,
			V: input.ID,
		}
	}
	// => Assets
	for _, asset := range input.Assets {
		if _, ok := mem.Assets[asset.ID]; !ok {
			return &ErrNotExist{
				K: KeyAsset,
				V: asset.ID,
			}
		}
	}

	// Save data
	// => Description
	if input.Description != nil {
		cve.Description = *input.Description
	}
	// => LastUpdate
	if input.LastUpdate != nil {
		cve.LastUpdate = *input.LastUpdate
	}
	// => CVSS2Vector
	if input.CVSS2Vector != nil {
		cve.CVSS2Vector = cpPtrValue(input.CVSS2Vector)
	}
	// => CVSS3Vector
	if input.CVSS3Vector != nil {
		cve.CVSS3Vector = cpPtrValue(input.CVSS3Vector)
	}
	// => Configurations
	if input.Configurations != nil {
		configurations := make([]*model.Node, len(input.Configurations))
		for i, conf := range input.Configurations {
			configurations[i] = loadInputConf(conf)
		}
		// Update index
		cveCPEs23 := getAllCPEs23(cve.Configurations)
		newCVECPEs23 := getAllCPEs23(configurations)
		for _, inputCPE23 := range newCVECPEs23 {
			found := false
			inputCPE23vp := internal.GetVP(inputCPE23)
			for _, cpe23 := range cveCPEs23 {
				if inputCPE23vp == internal.GetVP(cpe23) {
					found = true
					break
				}
			}
			if !found {
				// Add to index
				if _, ok := mem.CVEVPIndex[inputCPE23vp]; !ok {
					mem.CVEVPIndex[inputCPE23vp] = map[string]struct{}{}
				}
				mem.CVEVPIndex[inputCPE23vp][cve.ID] = struct{}{}
			}
		}
		for _, cpe23 := range cveCPEs23 {
			remains := false
			cpe23vp := internal.GetVP(cpe23)
			for _, inputCPE23 := range newCVECPEs23 {
				if cpe23vp == internal.GetVP(inputCPE23) {
					remains = true
					break
				}
			}
			if !remains {
				// Remove from index
				delete(mem.CVEVPIndex[cpe23vp], cve.ID)
				if len(mem.CVEVPIndex[cpe23vp]) == 0 {
					delete(mem.CVEVPIndex, cpe23vp)
				}
			}
		}
		cve.Configurations = configurations
	}
	// => Assets
	if input.Assets != nil {
		newAssets := make([]*model.Asset, len(input.Assets))
		for i, asset := range input.Assets {
			newAssets[i] = &model.Asset{
				ID: asset.ID,
			}
		}
		// Update assets
		for _, asset := range cve.Assets {
			remains := false
			for _, inputAsset := range input.Assets {
				if asset.ID == inputAsset.ID {
					remains = true
					break
				}
			}
			if !remains {
				// Remove link
				asset := mem.Assets[asset.ID]
				asset.CVEs = removeCVE(asset.CVEs, cve)
			}
		}
		for _, inputAsset := range input.Assets {
			found := false
			for _, asset := range cve.Assets {
				if inputAsset.ID == asset.ID {
					found = true
					break
				}
			}
			if !found {
				// Add link
				asset := mem.Assets[inputAsset.ID]
				asset.CVEs = append(asset.CVEs, &model.CVE{
					ID: cve.ID,
				})
			}
		}
		cve.Assets = newAssets
	}
	// => References
	if input.References != nil {
		cve.References = make([]*model.Reference, len(input.References))
		for i, ref := range input.References {
			tags := make([]string, len(ref.Tags))
			copy(tags, ref.Tags)
			cve.References[i] = &model.Reference{
				URL:       ref.URL,
				Name:      ref.Name,
				Refsource: ref.Refsource,
				Tags:      tags,
			}
		}
	}

	return nil
}

func (mem *Memory) DeleteCVE(input DeleteCVEInput) error {
	mem.mx.Lock()
	defer mem.mx.Unlock()

	// Check for consistency
	cve, ok := mem.CVEs[input.ID]
	if !ok {
		return &ErrNotExist{
			K: KeyCVE,
			V: input.ID,
		}
	}

	// Save data
	// => Assets
	for _, cveAsset := range cve.Assets {
		asset := mem.Assets[cveAsset.ID]
		asset.CVEs = removeCVE(asset.CVEs, cve)
	}
	// => Index
	cpes23 := getAllCPEs23(cve.Configurations)
	for _, cpe23 := range cpes23 {
		vp := internal.GetVP(cpe23)
		delete(mem.CVEVPIndex[vp], cve.ID)
		if len(mem.CVEVPIndex[vp]) == 0 {
			delete(mem.CVEVPIndex, vp)
		}
	}
	delete(mem.CVEs, input.ID)

	return nil
}

// Edges resolvers

// GetAssetCVEs returns a Asset's CVEs.
// As it is an edge resolver, it does not perform a check on
// the given pointer.
func (mem *Memory) GetAssetCVEs(asset *model.Asset) []*model.CVE {
	mem.mx.RLock()
	defer mem.mx.RUnlock()

	assetCVEs := asset.CVEs
	cves := make([]*model.CVE, len(assetCVEs))
	for i, cve := range assetCVEs {
		cves[i] = copyCVE(mem.CVEs[cve.ID])
	}
	return cves
}

// GetCVEAssets returns a CVE's Assets.
// As it is an edge resolver, it does not perform a check on the id.
func (mem *Memory) GetCVEAssets(cve *model.CVE) []*model.Asset {
	mem.mx.RLock()
	defer mem.mx.RUnlock()

	cveAssets := cve.Assets
	assets := make([]*model.Asset, len(cveAssets))
	for i, asset := range cveAssets {
		assets[i] = copyAsset(mem.Assets[asset.ID])
	}
	return assets
}

// Helpers

func loadInputConf(conf any) *model.Node {
	node := &model.Node{}
	b, _ := json.Marshal(conf)
	_ = json.Unmarshal(b, node)
	fillNilSlc(node)
	return node
}

func fillNilSlc(node *model.Node) {
	if node.CPEMatches == nil {
		node.CPEMatches = []*model.CPEMatch{}
	}
	if node.Children == nil {
		node.Children = []*model.Node{}
	} else {
		for _, child := range node.Children {
			fillNilSlc(child)
		}
	}
}

func getAllCPEs23(nodes []*model.Node) []string {
	slc := []string{}
	for _, node := range nodes {
		ndSlc := getNodeCPEs23(node)
		slc = append(slc, ndSlc...)
	}
	return slc
}

func getNodeCPEs23(node *model.Node) []string {
	slc := []string{}
	for _, child := range node.Children {
		childSlc := getNodeCPEs23(child)
		slc = append(slc, childSlc...)
	}
	for _, cpeMatch := range node.CPEMatches {
		slc = append(slc, cpeMatch.CPE23)
	}
	return slc
}

func copyAsset(asset *model.Asset) *model.Asset {
	parents := make([]*model.Asset, len(asset.Parents))
	for i, parent := range asset.Parents {
		parents[i] = &model.Asset{
			ID: parent.ID,
		}
	}
	children := make([]*model.Asset, len(asset.Children))
	for i, child := range asset.Children {
		children[i] = &model.Asset{
			ID: child.ID,
		}
	}
	cves := make([]*model.CVE, len(asset.CVEs))
	for i, cve := range asset.CVEs {
		cves[i] = &model.CVE{
			ID: cve.ID,
		}
	}
	return &model.Asset{
		ID:       asset.ID,
		Name:     asset.Name,
		CPE23:    asset.CPE23,
		Parents:  parents,
		Children: children,
		CVEs:     cves,
	}
}

func copyCVE(cve *model.CVE) *model.CVE {
	configurations := make([]*model.Node, len(cve.Configurations))
	for i, conf := range cve.Configurations {
		configurations[i] = copyNode(conf)
	}
	assets := make([]*model.Asset, len(cve.Assets))
	for i, asset := range cve.Assets {
		assets[i] = &model.Asset{
			ID: asset.ID,
		}
	}
	references := make([]*model.Reference, len(cve.References))
	for i, ref := range cve.References {
		tags := make([]string, len(ref.Tags))
		copy(tags, ref.Tags)
		references[i] = &model.Reference{
			URL:       ref.URL,
			Name:      ref.Name,
			Refsource: ref.Refsource,
			Tags:      tags,
		}
	}
	return &model.CVE{
		ID:              cve.ID,
		Description:     cve.Description,
		PublicationDate: cve.PublicationDate,
		LastUpdate:      cve.LastUpdate,
		CVSS2Vector:     cpPtrValue(cve.CVSS2Vector),
		CVSS3Vector:     cpPtrValue(cve.CVSS3Vector),
		Configurations:  configurations,
		Assets:          assets,
		References:      references,
	}
}

func copyNode(node *model.Node) *model.Node {
	children := make([]*model.Node, len(node.Children))
	for i, child := range node.Children {
		children[i] = copyNode(child)
	}
	matches := make([]*model.CPEMatch, len(node.CPEMatches))
	for i, cpeMatch := range node.CPEMatches {
		matches[i] = copyCPEMatch(cpeMatch)
	}
	return &model.Node{
		Negate:     cpPtrValue(node.Negate),
		Operator:   node.Operator,
		Children:   children,
		CPEMatches: matches,
	}
}

func copyCPEMatch(cpeMatch *model.CPEMatch) *model.CPEMatch {
	return &model.CPEMatch{
		Vulnerable:            cpeMatch.Vulnerable,
		CPE23:                 cpeMatch.CPE23,
		VersionStartIncluding: cpPtrValue(cpeMatch.VersionStartIncluding),
		VersionStartExcluding: cpPtrValue(cpeMatch.VersionStartExcluding),
		VersionEndIncluding:   cpPtrValue(cpeMatch.VersionEndIncluding),
		VersionEndExcluding:   cpPtrValue(cpeMatch.VersionEndExcluding),
	}
}

func cpPtrValue[T any](t *T) *T {
	if t == nil {
		return nil
	}
	v := *t
	return &v
}

func removeAsset(slc []*model.Asset, target *model.Asset) []*model.Asset {
	newSlc := make([]*model.Asset, len(slc)-1)
	i := 0
	for _, asset := range slc {
		if asset.ID == target.ID {
			continue
		}
		newSlc[i] = asset
		i++
	}
	return newSlc
}

func removeCVE(slc []*model.CVE, target *model.CVE) []*model.CVE {
	newSlc := make([]*model.CVE, len(slc)-1)
	i := 0
	for _, cve := range slc {
		if cve.ID == target.ID {
			continue
		}
		newSlc[i] = cve
		i++
	}
	return newSlc
}
