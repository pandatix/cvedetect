package db

import (
	"encoding/json"
	"sync"

	"github.com/knqyf263/go-cpe/matching"
	"github.com/knqyf263/go-cpe/naming"
	"github.com/pandatix/cvedetect/internal"
	"github.com/pandatix/cvedetect/model"
)

type Memory struct {
	mx sync.RWMutex

	// Components indexes *model.Component on to the ID
	Components map[string]*model.Component
	// CompVPIndex indexes *model.Component on the vendor:product
	// couple of the CPEs.
	// Second map indexes by the Component's ID.
	CompVPIndex map[string]map[string]struct{}

	// CVEs indexes *model.CVE on to the ID
	CVEs map[string]*model.CVE
	// CVEVPIndex indexes *model.CVE on the vendor:product couple
	// of the CPEs in its configurations.
	// Second map indexes by the CVE's ID.
	CVEVPIndex map[string]map[string]struct{}
}

func NewMemory() *Memory {
	return &Memory{
		mx:          sync.RWMutex{},
		Components:  map[string]*model.Component{},
		CompVPIndex: map[string]map[string]struct{}{},
		CVEs:        map[string]*model.CVE{},
		CVEVPIndex:  map[string]map[string]struct{}{},
	}
}

func (mem *Memory) GetComponent(input GetComponentInput) (*model.Component, error) {
	mem.mx.RLock()
	defer mem.mx.RUnlock()

	// Check for consistency
	comp, ok := mem.Components[input.ID]
	if !ok {
		return nil, &ErrNotExist{
			K: KeyComponent,
			V: input.ID,
		}
	}

	return copyComponent(comp), nil
}

func (mem *Memory) QueryComponents(input QueryComponentInput) []*model.Component {
	mem.mx.RLock()
	defer mem.mx.RUnlock()

	// Select components to query
	var mp map[string]*model.Component = mem.Components
	if input.VP != nil {
		v, p := splitVP(*input.VP)
		if containsWildcard(v) || containsWildcard(p) {
			// Select using subset
			inWFN, _ := naming.UnbindFS("cpe:2.3:a:" + *input.VP + "*:*:*:*:*:*:*:*")
			mp = map[string]*model.Component{}
			for vp, compsIDs := range mem.CompVPIndex {
				// XXX workaround as matching.compare is not directly accessible.
				compWFN, _ := naming.UnbindFS("cpe:2.3:a:" + vp + "*:*:*:*:*:*:*:*")
				if matching.IsSuperset(inWFN, compWFN) {
					for compID := range compsIDs {
						mp[compID] = mem.Components[compID]
					}
				}
			}
		} else {
			// Select directly
			mp = make(map[string]*model.Component, len(mem.CompVPIndex[*input.VP]))
			for compID := range mem.CompVPIndex[*input.VP] {
				mp[compID] = mem.Components[compID]
			}
		}
	}

	comps := make([]*model.Component, len(mp))
	i := 0
	for _, comp := range mp {
		comps[i] = copyComponent(comp)
		i++
	}
	return comps
}

func (mem *Memory) AddComponent(input AddComponentInput) error {
	mem.mx.Lock()
	defer mem.mx.Unlock()

	// Check for consistency
	if _, ok := mem.Components[input.ID]; ok {
		return &ErrAlreadyExist{
			K: KeyComponent,
			V: input.ID,
		}
	}
	if input.Parent != nil {
		if _, ok := mem.Components[input.Parent.ID]; !ok {
			return &ErrNotExist{
				K: KeyComponent,
				V: input.Parent.ID,
			}
		}
	}
	for _, child := range input.Children {
		if _, ok := mem.Components[child.ID]; !ok {
			return &ErrNotExist{
				K: KeyComponent,
				V: child.ID,
			}
		}
	}

	// Save data
	// => Components map
	children := make([]*model.Component, len(input.Children))
	for i, child := range input.Children {
		children[i] = &model.Component{
			ID: child.ID,
		}

		// Set child's parent relation
		child := mem.Components[child.ID]
		if child.Parent != nil {
			// Drop existing parent relation
			parent := mem.Components[child.Parent.ID]
			parent.Children = removeComponent(parent.Children, child)
		}
		child.Parent = &model.Component{
			ID: input.ID,
		}
	}
	var parent *model.Component = nil
	if input.Parent != nil {
		parent = &model.Component{
			ID: input.Parent.ID,
		}
	}
	mem.Components[input.ID] = &model.Component{
		ID:       input.ID,
		Name:     input.Name,
		CPE23:    input.CPE23,
		Parent:   parent,
		Children: children,
		CVEs:     []*model.CVE{},
	}
	// => Index map
	vp := internal.GetVP(input.CPE23)
	if _, ok := mem.CompVPIndex[vp]; !ok {
		mem.CompVPIndex[vp] = map[string]struct{}{}
	}
	mem.CompVPIndex[vp][input.ID] = struct{}{}

	return nil
}

func (mem *Memory) UpdateComponent(input UpdateComponentInput) error {
	mem.mx.Lock()
	defer mem.mx.Unlock()

	// Check for consistency
	// => Component
	comp, ok := mem.Components[input.ID]
	if !ok {
		return &ErrNotExist{
			K: KeyComponent,
			V: input.ID,
		}
	}
	// => Parent
	if input.Parent != nil {
		if _, ok := mem.Components[input.Parent.ID]; !ok {
			return &ErrNotExist{
				K: KeyComponent,
				V: input.Parent.ID,
			}
		}
	}
	// => Children
	for _, child := range input.Children {
		if _, ok := mem.Components[child.ID]; !ok {
			return &ErrNotExist{
				K: KeyComponent,
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

	// Save data
	// => Name
	if input.Name != nil {
		comp.Name = *input.Name
	}
	// => CPE23
	if input.CPE23 != nil {
		// Update index
		vpOld := internal.GetVP(comp.CPE23)
		vpNew := internal.GetVP(*input.CPE23)
		if vpNew != vpOld {
			// Delete old index
			delete(mem.CompVPIndex[vpOld], comp.ID)
			if len(mem.CompVPIndex[vpOld]) == 0 {
				delete(mem.CompVPIndex, vpOld)
			}

			// Add new index
			if _, ok := mem.CompVPIndex[vpNew]; !ok {
				mem.CompVPIndex[vpNew] = map[string]struct{}{}
			}
			mem.CompVPIndex[vpNew][comp.ID] = struct{}{}
		}
		comp.CPE23 = *input.CPE23
	}
	// => Parent
	if input.Parent != nil {
		if comp.Parent != nil {
			// Drop existing parent relation
			parent := mem.Components[comp.Parent.ID]
			parent.Children = removeComponent(parent.Children, comp)
		}
		comp.Parent = &model.Component{
			ID: input.Parent.ID,
		}
		newParent := mem.Components[input.Parent.ID]
		newParent.Children = append(newParent.Children, &model.Component{
			ID: comp.ID,
		})
	}
	// => Children
	if input.Children != nil {
		newChildren := make([]*model.Component, len(input.Children))
		for i, child := range input.Children {
			newChildren[i] = &model.Component{
				ID: child.ID,
			}
		}
		// Update children
		for _, child := range comp.Children {
			remains := false
			for _, inputChild := range input.Children {
				if child.ID == inputChild.ID {
					remains = true
					break
				}
			}
			if !remains {
				// Delete link
				child := mem.Components[child.ID]
				child.Parent = nil
			}
		}
		for _, inputChild := range input.Children {
			found := false
			for _, child := range comp.Children {
				if inputChild.ID == child.ID {
					found = true
					break
				}
			}
			if !found {
				child := mem.Components[inputChild.ID]
				child.Parent = &model.Component{
					ID: comp.ID,
				}
			}
		}
		comp.Children = newChildren
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
		for _, cve := range comp.CVEs {
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
				cve.Components = removeComponent(cve.Components, comp)
			}
		}
		for _, inputCVE := range input.CVEs {
			found := false
			for _, cve := range comp.CVEs {
				if inputCVE.ID == cve.ID {
					found = true
					break
				}
			}
			if !found {
				// Add link
				cve := mem.CVEs[inputCVE.ID]
				cve.Components = append(cve.Components, &model.Component{
					ID: comp.ID,
				})
			}
		}
		comp.CVEs = newCVES
	}

	return nil
}

func (mem *Memory) DeleteComponent(input DeleteComponentInput) error {
	mem.mx.Lock()
	defer mem.mx.Unlock()

	// Check for consistency
	comp, ok := mem.Components[input.ID]
	if !ok {
		return &ErrNotExist{
			K: KeyComponent,
			V: input.ID,
		}
	}

	// Save data
	// => Parent
	if comp.Parent != nil {
		parent := mem.Components[comp.Parent.ID]
		parent.Children = removeComponent(parent.Children, comp)
	}
	// => Children
	for _, compChild := range comp.Children {
		child := mem.Components[compChild.ID]
		child.Parent = nil
	}
	// => CVEs
	for _, compCve := range comp.CVEs {
		cve := mem.CVEs[compCve.ID]
		cve.Components = removeComponent(cve.Components, comp)
	}
	// => Index
	vp := internal.GetVP(comp.CPE23)
	delete(mem.CompVPIndex[vp], comp.ID)
	if len(mem.CompVPIndex[vp]) == 0 {
		delete(mem.CompVPIndex, vp)
	}
	delete(mem.Components, comp.ID)

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
				// XXX workaround as matching.compare is not directly accessible.
				compWFN, _ := naming.UnbindFS("cpe:2.3:a:" + vp + "*:*:*:*:*:*:*:*")
				if matching.IsSuperset(inWFN, compWFN) {
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
		CVSS20Vector:    cpPtrValue(input.CVSS20Vector),
		CVSS30Vector:    cpPtrValue(input.CVSS30Vector),
		CVSS31Vector:    cpPtrValue(input.CVSS31Vector),
		Configurations:  configurations,
		Components:      []*model.Component{},
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
	// => Components
	for _, comp := range input.Components {
		if _, ok := mem.Components[comp.ID]; !ok {
			return &ErrNotExist{
				K: KeyComponent,
				V: comp.ID,
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
	// => CVSS20Vector
	if input.CVSS20Vector != nil {
		cve.CVSS20Vector = cpPtrValue(input.CVSS20Vector)
	}
	// => CVSS30Vector
	if input.CVSS30Vector != nil {
		cve.CVSS30Vector = cpPtrValue(input.CVSS30Vector)
	}
	// => CVSS31Vector
	if input.CVSS31Vector != nil {
		cve.CVSS31Vector = cpPtrValue(input.CVSS31Vector)
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
	// => Components
	if input.Components != nil {
		newComps := make([]*model.Component, len(input.Components))
		for i, comp := range input.Components {
			newComps[i] = &model.Component{
				ID: comp.ID,
			}
		}
		// Update components
		for _, comp := range cve.Components {
			remains := false
			for _, inputComp := range input.Components {
				if comp.ID == inputComp.ID {
					remains = true
					break
				}
			}
			if !remains {
				// Remove link
				comp := mem.Components[comp.ID]
				comp.CVEs = removeCVE(comp.CVEs, cve)
			}
		}
		for _, inputComp := range input.Components {
			found := false
			for _, comp := range cve.Components {
				if inputComp.ID == comp.ID {
					found = true
					break
				}
			}
			if !found {
				// Add link
				comp := mem.Components[inputComp.ID]
				comp.CVEs = append(comp.CVEs, &model.CVE{
					ID: cve.ID,
				})
			}
		}
		cve.Components = newComps
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
	// => Components
	for _, cveComp := range cve.Components {
		comp := mem.Components[cveComp.ID]
		comp.CVEs = removeCVE(comp.CVEs, cve)
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

// GetComponentCVEs returns a Component's CVEs.
// As it is an edge resolver, it does not perform a check on
// the given pointer.
func (mem *Memory) GetComponentCVEs(comp *model.Component) []*model.CVE {
	mem.mx.RLock()
	defer mem.mx.RUnlock()

	compCVEs := comp.CVEs
	cves := make([]*model.CVE, len(compCVEs))
	for i, cve := range compCVEs {
		cves[i] = copyCVE(mem.CVEs[cve.ID])
	}
	return cves
}

// GetCVEComponents returns a CVE's Components.
// As it is an edge resolver, it does not perform a check on the id.
func (mem *Memory) GetCVEComponents(cve *model.CVE) []*model.Component {
	mem.mx.RLock()
	defer mem.mx.RUnlock()

	cveComps := cve.Components
	comps := make([]*model.Component, len(cveComps))
	for i, comp := range cveComps {
		comps[i] = copyComponent(mem.Components[comp.ID])
	}
	return comps
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

func copyComponent(comp *model.Component) *model.Component {
	children := make([]*model.Component, len(comp.Children))
	for i, child := range comp.Children {
		children[i] = &model.Component{
			ID: child.ID,
		}
	}
	cves := make([]*model.CVE, len(comp.CVEs))
	for i, cve := range comp.CVEs {
		cves[i] = &model.CVE{
			ID: cve.ID,
		}
	}
	parent := (*model.Component)(nil)
	if comp.Parent != nil {
		parent = &model.Component{
			ID: comp.Parent.ID,
		}
	}
	return &model.Component{
		ID:       comp.ID,
		Name:     comp.Name,
		CPE23:    comp.CPE23,
		Parent:   parent,
		Children: children,
		CVEs:     cves,
	}
}

func copyCVE(cve *model.CVE) *model.CVE {
	configurations := make([]*model.Node, len(cve.Configurations))
	for i, conf := range cve.Configurations {
		configurations[i] = copyNode(conf)
	}
	comps := make([]*model.Component, len(cve.Components))
	for i, comp := range cve.Components {
		comps[i] = &model.Component{
			ID: comp.ID,
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
		CVSS20Vector:    cpPtrValue(cve.CVSS20Vector),
		CVSS30Vector:    cpPtrValue(cve.CVSS30Vector),
		CVSS31Vector:    cpPtrValue(cve.CVSS31Vector),
		Configurations:  configurations,
		Components:      comps,
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

func removeComponent(slc []*model.Component, target *model.Component) []*model.Component {
	newSlc := make([]*model.Component, len(slc)-1)
	i := 0
	for _, comp := range slc {
		if comp.ID == target.ID {
			continue
		}
		newSlc[i] = comp
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
