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
	case *model.Component:
		t.Name += flag
		for i := 0; i < len(t.CPEs23); i++ {
			t.CPEs23[i] += flag
		}
		for i := 0; i < len(t.CVEs); i++ {
			t.CVEs[i].ID += flag
		}
		for i := 0; i < len(t.Children); i++ {
			t.Children[i].Name += flag
		}

	case *model.CVE:
		t.ID += flag
		for i := 0; i < len(t.Components); i++ {
			t.Components[i].Name += flag
		}
		for i := 0; i < len(t.Configurations); i++ {
			t.Configurations[i].Operator += flag
		}
	}
}

func unsem(mem *db.Memory) (dst any) {
	b, _ := json.Marshal(mem)
	json.Unmarshal(b, &dst)
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

func TestMemoryGetComponent(t *testing.T) {
	t.Parallel()

	var tests = map[string]struct {
		Memory            *db.Memory
		Input             db.GetComponentInput
		ExpectedComponent *model.Component
		ExpectedErr       error
		ExpectedMemory    *db.Memory
	}{
		"unexisting-component": {
			Memory: &db.Memory{
				Components:  map[string]*model.Component{},
				CVEs:        map[string]*model.CVE{},
				CompVPIndex: map[string]map[string]struct{}{},
				CVEVPIndex:  map[string]map[string]struct{}{},
			},
			Input: db.GetComponentInput{
				ID: "comp",
			},
			ExpectedComponent: nil,
			ExpectedErr: &db.ErrNotExist{
				K: db.KeyComponent,
				V: "comp",
			},
			ExpectedMemory: &db.Memory{
				Components:  map[string]*model.Component{},
				CVEs:        map[string]*model.CVE{},
				CompVPIndex: map[string]map[string]struct{}{},
				CVEVPIndex:  map[string]map[string]struct{}{},
			},
		},
		"existing-component": {
			Memory: &db.Memory{
				Components: map[string]*model.Component{
					"comp": {
						ID:       "comp",
						Name:     "Component",
						CPEs23:   []string{"cpe:2.3:a:fake:component:*:*:*:*:*:*:*:*"},
						Parent:   nil,
						Children: []*model.Component{},
						CVEs:     []*model.CVE{},
					},
				},
				CVEs: map[string]*model.CVE{},
				CompVPIndex: map[string]map[string]struct{}{
					"fake:component": {
						"comp": {},
					},
				},
				CVEVPIndex: map[string]map[string]struct{}{},
			},
			Input: db.GetComponentInput{
				ID: "comp",
			},
			ExpectedComponent: &model.Component{
				ID:       "comp",
				Name:     "Component",
				CPEs23:   []string{"cpe:2.3:a:fake:component:*:*:*:*:*:*:*:*"},
				Parent:   nil,
				Children: []*model.Component{},
				CVEs:     []*model.CVE{},
			},
			ExpectedErr: nil,
			ExpectedMemory: &db.Memory{
				Components: map[string]*model.Component{
					"comp": {
						ID:       "comp",
						Name:     "Component",
						CPEs23:   []string{"cpe:2.3:a:fake:component:*:*:*:*:*:*:*:*"},
						Parent:   nil,
						Children: []*model.Component{},
						CVEs:     []*model.CVE{},
					},
				},
				CompVPIndex: map[string]map[string]struct{}{
					"fake:component": {
						"comp": {},
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

			comp, err := tt.Memory.GetComponent(tt.Input)

			assert.Equal(tt.ExpectedComponent, comp)
			assert.Equal(tt.ExpectedErr, err)
			assertEqual(tt.ExpectedMemory, tt.Memory, assert)

			// Check return can't be modified
			if comp != nil {
				alter(comp)

				assertEqual(tt.ExpectedMemory, tt.Memory, assert)
			}
		})
	}
}

func TestMemoryQueryComponents(t *testing.T) {
	t.Parallel()

	var tests = map[string]struct {
		Memory             *db.Memory
		Input              db.QueryComponentInput
		ExpectedComponents []*model.Component
		ExpectedMemory     *db.Memory
	}{
		"no-components": {
			Memory: &db.Memory{
				Components:  map[string]*model.Component{},
				CompVPIndex: map[string]map[string]struct{}{},
				CVEs:        map[string]*model.CVE{},
				CVEVPIndex:  map[string]map[string]struct{}{},
			},
			Input: db.QueryComponentInput{
				VP: nil,
			},
			ExpectedComponents: []*model.Component{},
			ExpectedMemory: &db.Memory{
				Components:  map[string]*model.Component{},
				CompVPIndex: map[string]map[string]struct{}{},
				CVEs:        map[string]*model.CVE{},
				CVEVPIndex:  map[string]map[string]struct{}{},
			},
		},
		"multiple-components": {
			Memory: &db.Memory{
				Components: map[string]*model.Component{
					"comp-1": {
						ID:       "comp-1",
						Name:     "Component 1",
						CPEs23:   []string{"cpe:2.3:a:fake:component:1:*:*:*:*:*:*:*"},
						Parent:   nil,
						Children: []*model.Component{},
						CVEs:     []*model.CVE{},
					},
					"comp-2": {
						ID:       "comp-2",
						Name:     "Component 2",
						CPEs23:   []string{"cpe:2.3:a:fake:component:2:*:*:*:*:*:*:*"},
						Parent:   nil,
						Children: []*model.Component{},
						CVEs:     []*model.CVE{},
					},
				},
				CompVPIndex: map[string]map[string]struct{}{
					"fake:component": {
						"comp-1": {},
						"comp-2": {},
					},
				},
				CVEs:       map[string]*model.CVE{},
				CVEVPIndex: map[string]map[string]struct{}{},
			},
			Input: db.QueryComponentInput{
				VP: nil,
			},
			ExpectedComponents: []*model.Component{
				{
					ID:       "comp-1",
					Name:     "Component 1",
					CPEs23:   []string{"cpe:2.3:a:fake:component:1:*:*:*:*:*:*:*"},
					Parent:   nil,
					Children: []*model.Component{},
					CVEs:     []*model.CVE{},
				}, {
					ID:       "comp-2",
					Name:     "Component 2",
					CPEs23:   []string{"cpe:2.3:a:fake:component:2:*:*:*:*:*:*:*"},
					Parent:   nil,
					Children: []*model.Component{},
					CVEs:     []*model.CVE{},
				},
			},
			ExpectedMemory: &db.Memory{
				Components: map[string]*model.Component{
					"comp-1": {
						ID:       "comp-1",
						Name:     "Component 1",
						CPEs23:   []string{"cpe:2.3:a:fake:component:1:*:*:*:*:*:*:*"},
						Parent:   nil,
						Children: []*model.Component{},
						CVEs:     []*model.CVE{},
					},
					"comp-2": {
						ID:       "comp-2",
						Name:     "Component 2",
						CPEs23:   []string{"cpe:2.3:a:fake:component:2:*:*:*:*:*:*:*"},
						Parent:   nil,
						Children: []*model.Component{},
						CVEs:     []*model.CVE{},
					},
				},
				CompVPIndex: map[string]map[string]struct{}{
					"fake:component": {
						"comp-1": {},
						"comp-2": {},
					},
				},
				CVEs:       map[string]*model.CVE{},
				CVEVPIndex: map[string]map[string]struct{}{},
			},
		},
		"indexed-component": {
			Memory: &db.Memory{
				Components: map[string]*model.Component{
					"comp-1": {
						ID:       "comp-1",
						Name:     "Component 1",
						CPEs23:   []string{"cpe:2.3:a:fake:component:1:*:*:*:*:*:*:*"},
						Parent:   nil,
						Children: []*model.Component{},
						CVEs:     []*model.CVE{},
					},
					"comp-2": {
						ID:       "comp-2",
						Name:     "Component 2",
						CPEs23:   []string{"cpe:2.3:a:fake\\_new:component:2:*:*:*:*:*:*:*"},
						Parent:   nil,
						Children: []*model.Component{},
						CVEs:     []*model.CVE{},
					},
				},
				CompVPIndex: map[string]map[string]struct{}{
					"fake:component": {
						"comp-1": {},
					},
					"fake\\_new:component": {
						"comp-2": {},
					},
				},
				CVEs:       map[string]*model.CVE{},
				CVEVPIndex: map[string]map[string]struct{}{},
			},
			Input: db.QueryComponentInput{
				VP: ptr("fake\\_new:component"),
			},
			ExpectedComponents: []*model.Component{
				{
					ID:       "comp-2",
					Name:     "Component 2",
					CPEs23:   []string{"cpe:2.3:a:fake\\_new:component:2:*:*:*:*:*:*:*"},
					Parent:   nil,
					Children: []*model.Component{},
					CVEs:     []*model.CVE{},
				},
			},
			ExpectedMemory: &db.Memory{
				Components: map[string]*model.Component{
					"comp-1": {
						ID:       "comp-1",
						Name:     "Component 1",
						CPEs23:   []string{"cpe:2.3:a:fake:component:1:*:*:*:*:*:*:*"},
						Parent:   nil,
						Children: []*model.Component{},
						CVEs:     []*model.CVE{},
					},
					"comp-2": {
						ID:       "comp-2",
						Name:     "Component 2",
						CPEs23:   []string{"cpe:2.3:a:fake\\_new:component:2:*:*:*:*:*:*:*"},
						Parent:   nil,
						Children: []*model.Component{},
						CVEs:     []*model.CVE{},
					},
				},
				CompVPIndex: map[string]map[string]struct{}{
					"fake:component": {
						"comp-1": {},
					},
					"fake\\_new:component": {
						"comp-2": {},
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

			comps := tt.Memory.QueryComponents(tt.Input)

			assert.ElementsMatch(tt.ExpectedComponents, comps)

			// Check return can't be modified
			for i := 0; i < len(comps); i++ {
				alter(comps[i])
			}
			assertEqual(tt.ExpectedMemory, tt.Memory, assert)
		})
	}
}

func TestMemoryAddComponent(t *testing.T) {
	t.Parallel()

	var tests = map[string]struct {
		Memory         *db.Memory
		Input          db.AddComponentInput
		ExpectedErr    error
		ExpectedMemory *db.Memory
	}{
		"comp-exist": {
			Memory: &db.Memory{
				Components: map[string]*model.Component{
					"comp": {
						ID:       "comp",
						Name:     "Component",
						CPEs23:   []string{"cpe:2.3:a:fake:component:*:*:*:*:*:*:*:*"},
						Parent:   nil,
						Children: []*model.Component{},
						CVEs:     []*model.CVE{},
					},
				},
				CompVPIndex: map[string]map[string]struct{}{
					"fake:component": {
						"comp": {},
					},
				},
				CVEs:       map[string]*model.CVE{},
				CVEVPIndex: map[string]map[string]struct{}{},
			},
			Input: db.AddComponentInput{
				ID:       "comp",
				Name:     "Component",
				CPEs23:   []string{"cpe:2.3:a:fake:component:*:*:*:*:*:*:*:*"},
				Children: nil,
			},
			ExpectedErr: &db.ErrAlreadyExist{
				K: db.KeyComponent,
				V: "comp",
			},
			ExpectedMemory: &db.Memory{
				Components: map[string]*model.Component{
					"comp": {
						ID:       "comp",
						Name:     "Component",
						CPEs23:   []string{"cpe:2.3:a:fake:component:*:*:*:*:*:*:*:*"},
						Parent:   nil,
						Children: []*model.Component{},
						CVEs:     []*model.CVE{},
					},
				},
				CompVPIndex: map[string]map[string]struct{}{
					"fake:component": {
						"comp": {},
					},
				},
				CVEs:       map[string]*model.CVE{},
				CVEVPIndex: map[string]map[string]struct{}{},
			},
		},
		"parent-not-exist": {
			Memory: &db.Memory{
				Components:  map[string]*model.Component{},
				CompVPIndex: map[string]map[string]struct{}{},
				CVEs:        map[string]*model.CVE{},
				CVEVPIndex:  map[string]map[string]struct{}{},
			},
			Input: db.AddComponentInput{
				ID:     "comp",
				Name:   "Component",
				CPEs23: []string{"cpe:2.3:a:fake:component:*:*:*:*:*:*:*:*"},
				Parent: &db.AddComponentParent{
					ID: "unexisting-comp",
				},
				Children: []db.AddComponentChildInput{},
			},
			ExpectedErr: &db.ErrNotExist{
				K: db.KeyComponent,
				V: "unexisting-comp",
			},
			ExpectedMemory: &db.Memory{
				Components:  map[string]*model.Component{},
				CompVPIndex: map[string]map[string]struct{}{},
				CVEs:        map[string]*model.CVE{},
				CVEVPIndex:  map[string]map[string]struct{}{},
			},
		},
		"child-not-exist": {
			Memory: &db.Memory{
				Components:  map[string]*model.Component{},
				CompVPIndex: map[string]map[string]struct{}{},
				CVEs:        map[string]*model.CVE{},
				CVEVPIndex:  map[string]map[string]struct{}{},
			},
			Input: db.AddComponentInput{
				ID:     "comp",
				Name:   "Component",
				CPEs23: []string{"cpe:2.3:a:fake:component:*:*:*:*:*:*:*:*"},
				Children: []db.AddComponentChildInput{
					{
						ID: "unexisting-comp",
					},
				},
			},
			ExpectedErr: &db.ErrNotExist{
				K: db.KeyComponent,
				V: "unexisting-comp",
			},
			ExpectedMemory: &db.Memory{
				Components:  map[string]*model.Component{},
				CompVPIndex: map[string]map[string]struct{}{},
				CVEs:        map[string]*model.CVE{},
				CVEVPIndex:  map[string]map[string]struct{}{},
			},
		},
		"new-component": {
			Memory: &db.Memory{
				Components: map[string]*model.Component{
					"comp-parent": {
						ID:       "comp-parent",
						Name:     "Component Parent",
						CPEs23:   []string{"cpe:2.3:a:fake:component:*:parent:*:*:*:*:*:*"},
						Parent:   nil,
						Children: []*model.Component{},
						CVEs:     []*model.CVE{},
					},
					"comp-child-1": {
						ID:     "comp-child-1",
						Name:   "Component Child 1",
						CPEs23: []string{"cpe:2.3:a:fake:component:1:child:*:*:*:*:*:*"},
						Parent: nil,
						Children: []*model.Component{
							{
								ID: "comp-child-2",
							},
						},
						CVEs: []*model.CVE{},
					},
					"comp-child-2": {
						ID:     "comp-child-2",
						Name:   "Component Child 2",
						CPEs23: []string{"cpe:2.3:a:fake:component:2:child:*:*:*:*:*:*"},
						Parent: &model.Component{
							ID: "comp-child-1",
						},
						Children: []*model.Component{},
						CVEs:     []*model.CVE{},
					},
				},
				CompVPIndex: map[string]map[string]struct{}{
					"fake:component": {
						"comp-parent":  {},
						"comp-child-1": {},
						"comp-child-2": {},
					},
				},
				CVEs: map[string]*model.CVE{},
			},
			Input: db.AddComponentInput{
				ID:     "comp",
				Name:   "Component",
				CPEs23: []string{"cpe:2.3:a:fake\\_new:component:*:*:*:*:*:*:*:*"},
				Parent: &db.AddComponentParent{
					ID: "comp-parent",
				},
				Children: []db.AddComponentChildInput{
					{
						ID: "comp-child-1",
					}, {
						ID: "comp-child-2",
					},
				},
			},
			ExpectedErr: nil,
			ExpectedMemory: &db.Memory{
				Components: map[string]*model.Component{
					"comp-parent": {
						ID:       "comp-parent",
						Name:     "Component Parent",
						CPEs23:   []string{"cpe:2.3:a:fake:component:*:parent:*:*:*:*:*:*"},
						Parent:   nil,
						Children: []*model.Component{},
						CVEs:     []*model.CVE{},
					},
					"comp": {
						ID:     "comp",
						Name:   "Component",
						CPEs23: []string{"cpe:2.3:a:fake\\_new:component:*:*:*:*:*:*:*:*"},
						Parent: &model.Component{
							ID: "comp-parent",
						},
						Children: []*model.Component{
							{
								ID: "comp-child-1",
							}, {
								ID: "comp-child-2",
							},
						},
						CVEs: []*model.CVE{},
					},
					"comp-child-1": {
						ID:     "comp-child-1",
						Name:   "Component Child 1",
						CPEs23: []string{"cpe:2.3:a:fake:component:1:child:*:*:*:*:*:*"},
						Parent: &model.Component{
							ID: "comp",
						},
						Children: []*model.Component{},
						CVEs:     []*model.CVE{},
					},
					"comp-child-2": {
						ID:     "comp-child-2",
						Name:   "Component Child 2",
						CPEs23: []string{"cpe:2.3:a:fake:component:2:child:*:*:*:*:*:*"},
						Parent: &model.Component{
							ID: "comp",
						},
						Children: []*model.Component{},
						CVEs:     []*model.CVE{},
					},
				},
				CompVPIndex: map[string]map[string]struct{}{
					"fake:component": {
						"comp-parent":  {},
						"comp-child-1": {},
						"comp-child-2": {},
					},
					"fake\\_new:component": {
						"comp": {},
					},
				},
				CVEs: map[string]*model.CVE{},
			},
		},
		"comp-parent-already-exist": {
			Memory: &db.Memory{
				Components: map[string]*model.Component{
					"comp-parent": {
						ID:     "comp-parent",
						Name:   "Component Parent",
						CPEs23: []string{"cpe:2.3:a:fake:component:*:*:*:*:*:*:*:*"},
						Parent: nil,
						Children: []*model.Component{
							{
								ID: "comp",
							},
						},
						CVEs: []*model.CVE{},
					},
					"comp": {
						ID:     "comp",
						Name:   "Component",
						CPEs23: []string{},
						Parent: &model.Component{
							ID: "comp-parent",
						},
						Children: []*model.Component{},
						CVEs:     []*model.CVE{},
					},
				},
				CompVPIndex: map[string]map[string]struct{}{
					"fake:component": {
						"comp-parent": {},
					},
				},
				CVEs:       map[string]*model.CVE{},
				CVEVPIndex: map[string]map[string]struct{}{},
			},
			Input: db.AddComponentInput{
				ID:     "comp-new-parent",
				Name:   "Component New Parent",
				CPEs23: []string{"cpe:2.3:a:fake:component:*:*:*:*:*:*:*:*"},
				Children: []db.AddComponentChildInput{
					{
						ID: "comp",
					},
				},
			},
			ExpectedErr: nil,
			ExpectedMemory: &db.Memory{
				Components: map[string]*model.Component{
					"comp-parent": {
						ID:       "comp-parent",
						Name:     "Component Parent",
						CPEs23:   []string{"cpe:2.3:a:fake:component:*:*:*:*:*:*:*:*"},
						Parent:   nil,
						Children: []*model.Component{},
						CVEs:     []*model.CVE{},
					},
					"comp": {
						ID:     "comp",
						Name:   "Component",
						CPEs23: []string{},
						Parent: &model.Component{
							ID: "comp-new-parent",
						},
						Children: []*model.Component{},
						CVEs:     []*model.CVE{},
					},
					"comp-new-parent": {
						ID:     "comp-new-parent",
						Name:   "Component New Parent",
						CPEs23: []string{"cpe:2.3:a:fake:component:*:*:*:*:*:*:*:*"},
						Parent: nil,
						Children: []*model.Component{
							{
								ID: "comp",
							},
						},
						CVEs: []*model.CVE{},
					},
				},
				CompVPIndex: map[string]map[string]struct{}{
					"fake:component": {
						"comp-parent":     {},
						"comp-new-parent": {},
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

			err := tt.Memory.AddComponent(tt.Input)

			assert.Equal(tt.ExpectedErr, err)
			assertEqual(tt.ExpectedMemory, tt.Memory, assert)
		})
	}
}

func TestMemoryUpdateComponent(t *testing.T) {
	t.Parallel()

	var tests = map[string]struct {
		Memory         *db.Memory
		Input          db.UpdateComponentInput
		ExpectedErr    error
		ExpectedMemory *db.Memory
	}{
		"comp-not-exist": {
			Memory: &db.Memory{
				Components:  map[string]*model.Component{},
				CompVPIndex: map[string]map[string]struct{}{},
				CVEs:        map[string]*model.CVE{},
				CVEVPIndex:  map[string]map[string]struct{}{},
			},
			Input: db.UpdateComponentInput{
				ID:       "comp",
				Name:     nil,
				CPEs23:   nil,
				Children: nil,
				CVEs:     nil,
			},
			ExpectedErr: &db.ErrNotExist{
				K: db.KeyComponent,
				V: "comp",
			},
			ExpectedMemory: &db.Memory{
				Components:  map[string]*model.Component{},
				CompVPIndex: map[string]map[string]struct{}{},
				CVEs:        map[string]*model.CVE{},
				CVEVPIndex:  map[string]map[string]struct{}{},
			},
		},
		"parent-not-exist": {
			Memory: &db.Memory{
				Components: map[string]*model.Component{
					"comp": {
						ID:       "comp",
						Name:     "Component",
						CPEs23:   []string{"cpe:2.3:a:fake:component:*:*:*:*:*:*:*:*"},
						Parent:   nil,
						Children: []*model.Component{},
						CVEs:     []*model.CVE{},
					},
				},
				CompVPIndex: map[string]map[string]struct{}{
					"fake:component": {
						"comp": {},
					},
				},
				CVEs:       map[string]*model.CVE{},
				CVEVPIndex: map[string]map[string]struct{}{},
			},
			Input: db.UpdateComponentInput{
				ID:     "comp",
				Name:   nil,
				CPEs23: nil,
				Parent: &db.UpdateComponentParentInput{
					ID: "comp-parent",
				},
				Children: nil,
				CVEs:     nil,
			},
			ExpectedErr: &db.ErrNotExist{
				K: db.KeyComponent,
				V: "comp-parent",
			},
			ExpectedMemory: &db.Memory{
				Components: map[string]*model.Component{
					"comp": {
						ID:       "comp",
						Name:     "Component",
						CPEs23:   []string{"cpe:2.3:a:fake:component:*:*:*:*:*:*:*:*"},
						Parent:   nil,
						Children: []*model.Component{},
						CVEs:     []*model.CVE{},
					},
				},
				CompVPIndex: map[string]map[string]struct{}{
					"fake:component": {
						"comp": {},
					},
				},
				CVEs:       map[string]*model.CVE{},
				CVEVPIndex: map[string]map[string]struct{}{},
			},
		},
		"child-not-exist": {
			Memory: &db.Memory{
				Components: map[string]*model.Component{
					"comp": {
						ID:       "comp",
						Name:     "Component",
						CPEs23:   []string{"cpe:2.3:a:fake:component:*:*:*:*:*:*:*:*"},
						Parent:   nil,
						Children: []*model.Component{},
						CVEs:     []*model.CVE{},
					},
				},
				CompVPIndex: map[string]map[string]struct{}{
					"fake:component": {
						"comp": {},
					},
				},
				CVEs:       map[string]*model.CVE{},
				CVEVPIndex: map[string]map[string]struct{}{},
			},
			Input: db.UpdateComponentInput{
				ID:     "comp",
				Name:   nil,
				CPEs23: nil,
				Children: []db.UpdateComponentChildInput{
					{
						ID: "comp-child",
					},
				},
				CVEs: nil,
			},
			ExpectedErr: &db.ErrNotExist{
				K: db.KeyComponent,
				V: "comp-child",
			},
			ExpectedMemory: &db.Memory{
				Components: map[string]*model.Component{
					"comp": {
						ID:       "comp",
						Name:     "Component",
						CPEs23:   []string{"cpe:2.3:a:fake:component:*:*:*:*:*:*:*:*"},
						Parent:   nil,
						Children: []*model.Component{},
						CVEs:     []*model.CVE{},
					},
				},
				CompVPIndex: map[string]map[string]struct{}{
					"fake:component": {
						"comp": {},
					},
				},
				CVEs:       map[string]*model.CVE{},
				CVEVPIndex: map[string]map[string]struct{}{},
			},
		},
		"cve-not-exist": {
			Memory: &db.Memory{
				Components: map[string]*model.Component{
					"comp": {
						ID:       "comp",
						Name:     "Component",
						CPEs23:   []string{"cpe:2.3:a:fake:component:*:*:*:*:*:*:*:*"},
						Parent:   nil,
						Children: []*model.Component{},
						CVEs:     []*model.CVE{},
					},
				},
				CompVPIndex: map[string]map[string]struct{}{
					"fake:component": {
						"comp": {},
					},
				},
				CVEs:       map[string]*model.CVE{},
				CVEVPIndex: map[string]map[string]struct{}{},
			},
			Input: db.UpdateComponentInput{
				ID:       "comp",
				Name:     nil,
				CPEs23:   nil,
				Children: nil,
				CVEs: []db.UpdateComponentCVEsInput{
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
				Components: map[string]*model.Component{
					"comp": {
						ID:       "comp",
						Name:     "Component",
						CPEs23:   []string{"cpe:2.3:a:fake:component:*:*:*:*:*:*:*:*"},
						Parent:   nil,
						Children: []*model.Component{},
						CVEs:     []*model.CVE{},
					},
				},
				CompVPIndex: map[string]map[string]struct{}{
					"fake:component": {
						"comp": {},
					},
				},
				CVEs:       map[string]*model.CVE{},
				CVEVPIndex: map[string]map[string]struct{}{},
			},
		},
		"new-name": {
			Memory: &db.Memory{
				Components: map[string]*model.Component{
					"comp": {
						ID:       "comp",
						Name:     "Component",
						CPEs23:   []string{"cpe:2.3:a:fake:component:*:*:*:*:*:*:*:*"},
						Parent:   nil,
						Children: []*model.Component{},
						CVEs:     []*model.CVE{},
					},
				},
				CompVPIndex: map[string]map[string]struct{}{
					"fake:component": {
						"comp": {},
					},
				},
				CVEs:       map[string]*model.CVE{},
				CVEVPIndex: map[string]map[string]struct{}{},
			},
			Input: db.UpdateComponentInput{
				ID:       "comp",
				Name:     ptr("New Component"),
				CPEs23:   nil,
				Children: nil,
				CVEs:     nil,
			},
			ExpectedErr: nil,
			ExpectedMemory: &db.Memory{
				Components: map[string]*model.Component{
					"comp": {
						ID:       "comp",
						Name:     "New Component",
						CPEs23:   []string{"cpe:2.3:a:fake:component:*:*:*:*:*:*:*:*"},
						Parent:   nil,
						Children: []*model.Component{},
						CVEs:     []*model.CVE{},
					},
				},
				CompVPIndex: map[string]map[string]struct{}{
					"fake:component": {
						"comp": {},
					},
				},
				CVEs:       map[string]*model.CVE{},
				CVEVPIndex: map[string]map[string]struct{}{},
			},
		},
		"new-cpes23": {
			Memory: &db.Memory{
				Components: map[string]*model.Component{
					"comp": {
						ID:   "comp",
						Name: "Component",
						CPEs23: []string{
							"cpe:2.3:a:fake:component:1:*:*:*:*:*:*:*",
							"cpe:2.3:a:fake\\_other:component:2:*:*:*:*:*:*:*",
						},
						Parent:   nil,
						Children: []*model.Component{},
						CVEs:     []*model.CVE{},
					},
				},
				CompVPIndex: map[string]map[string]struct{}{
					"fake:component": {
						"comp": {},
					},
					"fake\\_other:component": {
						"comp": {},
					},
				},
				CVEs:       map[string]*model.CVE{},
				CVEVPIndex: map[string]map[string]struct{}{},
			},
			Input: db.UpdateComponentInput{
				ID:   "comp",
				Name: nil,
				CPEs23: []string{
					"cpe:2.3:a:fake\\_other:component:2:*:*:*:*:*:*:*",
					"cpe:2.3:a:fake\\_new:component:3:*:*:*:*:*:*:*",
				},
				Parent:   nil,
				Children: nil,
				CVEs:     nil,
			},
			ExpectedErr: nil,
			ExpectedMemory: &db.Memory{
				Components: map[string]*model.Component{
					"comp": {
						ID:   "comp",
						Name: "Component",
						CPEs23: []string{
							"cpe:2.3:a:fake\\_other:component:2:*:*:*:*:*:*:*",
							"cpe:2.3:a:fake\\_new:component:3:*:*:*:*:*:*:*",
						},
						Parent:   nil,
						Children: []*model.Component{},
						CVEs:     []*model.CVE{},
					},
				},
				CompVPIndex: map[string]map[string]struct{}{
					"fake\\_other:component": {
						"comp": {},
					},
					"fake\\_new:component": {
						"comp": {},
					},
				},
				CVEs:       map[string]*model.CVE{},
				CVEVPIndex: map[string]map[string]struct{}{},
			},
		},
		"new-parent": {
			Memory: &db.Memory{
				Components: map[string]*model.Component{
					"comp": {
						ID:       "comp",
						Name:     "Component",
						CPEs23:   []string{"cpe:2.3:a:fake:component:*:*:*:*:*:*:*:*"},
						Parent:   nil,
						Children: []*model.Component{},
						CVEs:     []*model.CVE{},
					},
					"comp-parent": {
						ID:       "comp-parent",
						Name:     "Component Parent",
						CPEs23:   []string{"cpe:2.3:a:fake:component:*:parent:*:*:*:*:*:*"},
						Parent:   nil,
						Children: []*model.Component{},
						CVEs:     []*model.CVE{},
					},
				},
				CompVPIndex: map[string]map[string]struct{}{
					"fake:component": {
						"comp":        {},
						"comp-parent": {},
					},
				},
				CVEs:       map[string]*model.CVE{},
				CVEVPIndex: map[string]map[string]struct{}{},
			},
			Input: db.UpdateComponentInput{
				ID:     "comp",
				Name:   nil,
				CPEs23: nil,
				Parent: &db.UpdateComponentParentInput{
					ID: "comp-parent",
				},
				Children: nil,
				CVEs:     nil,
			},
			ExpectedErr: nil,
			ExpectedMemory: &db.Memory{
				Components: map[string]*model.Component{
					"comp": {
						ID:     "comp",
						Name:   "Component",
						CPEs23: []string{"cpe:2.3:a:fake:component:*:*:*:*:*:*:*:*"},
						Parent: &model.Component{
							ID: "comp-parent",
						},
						Children: []*model.Component{},
						CVEs:     []*model.CVE{},
					},
					"comp-parent": {
						ID:     "comp-parent",
						Name:   "Component Parent",
						CPEs23: []string{"cpe:2.3:a:fake:component:*:parent:*:*:*:*:*:*"},
						Parent: nil,
						Children: []*model.Component{
							{
								ID: "comp",
							},
						},
						CVEs: []*model.CVE{},
					},
				},
				CompVPIndex: map[string]map[string]struct{}{
					"fake:component": {
						"comp":        {},
						"comp-parent": {},
					},
				},
				CVEs:       map[string]*model.CVE{},
				CVEVPIndex: map[string]map[string]struct{}{},
			},
		},
		"new-parent-already-existing": {
			Memory: &db.Memory{
				Components: map[string]*model.Component{
					"comp-parent": {
						ID:     "comp-parent",
						Name:   "Component Parent",
						CPEs23: []string{"cpe:2.3:a:fake:component:*:parent:*:*:*:*:*:*"},
						Parent: nil,
						Children: []*model.Component{
							{
								ID: "comp",
							},
						},
						CVEs: []*model.CVE{},
					},
					"comp": {
						ID:     "comp",
						Name:   "Component",
						CPEs23: []string{"cpe:2.3:a:fake:component:*:*:*:*:*:*:*:*"},
						Parent: &model.Component{
							ID: "comp-parent",
						},
						Children: []*model.Component{},
						CVEs:     []*model.CVE{},
					},
					"comp-future-parent": {
						ID:       "comp-future-parent",
						Name:     "Component Future Parent",
						CPEs23:   []string{"cpe:2.3:a:fake:component:*:parent:*:*:*:*:*:*"},
						Parent:   nil,
						Children: []*model.Component{},
						CVEs:     []*model.CVE{},
					},
				},
				CompVPIndex: map[string]map[string]struct{}{
					"fake:component": {
						"comp":               {},
						"comp-parent":        {},
						"comp-future-parent": {},
					},
				},
				CVEs:       map[string]*model.CVE{},
				CVEVPIndex: map[string]map[string]struct{}{},
			},
			Input: db.UpdateComponentInput{
				ID:     "comp",
				Name:   nil,
				CPEs23: nil,
				Parent: &db.UpdateComponentParentInput{
					ID: "comp-future-parent",
				},
				Children: nil,
				CVEs:     nil,
			},
			ExpectedErr: nil,
			ExpectedMemory: &db.Memory{
				Components: map[string]*model.Component{
					"comp-parent": {
						ID:       "comp-parent",
						Name:     "Component Parent",
						CPEs23:   []string{"cpe:2.3:a:fake:component:*:parent:*:*:*:*:*:*"},
						Parent:   nil,
						Children: []*model.Component{},
						CVEs:     []*model.CVE{},
					},
					"comp": {
						ID:     "comp",
						Name:   "Component",
						CPEs23: []string{"cpe:2.3:a:fake:component:*:*:*:*:*:*:*:*"},
						Parent: &model.Component{
							ID: "comp-future-parent",
						},
						Children: []*model.Component{},
						CVEs:     []*model.CVE{},
					},
					"comp-future-parent": {
						ID:     "comp-future-parent",
						Name:   "Component Future Parent",
						CPEs23: []string{"cpe:2.3:a:fake:component:*:parent:*:*:*:*:*:*"},
						Parent: nil,
						Children: []*model.Component{
							{
								ID: "comp",
							},
						},
						CVEs: []*model.CVE{},
					},
				},
				CompVPIndex: map[string]map[string]struct{}{
					"fake:component": {
						"comp":               {},
						"comp-parent":        {},
						"comp-future-parent": {},
					},
				},
				CVEs:       map[string]*model.CVE{},
				CVEVPIndex: map[string]map[string]struct{}{},
			},
		},
		"new-children": {
			Memory: &db.Memory{
				Components: map[string]*model.Component{
					"comp": {
						ID:     "comp",
						Name:   "Component",
						CPEs23: []string{"cpe:2.3:a:fake:component:*:*:*:*:*:*:*:*"},
						Parent: nil,
						Children: []*model.Component{
							{
								ID: "comp-child-1",
							}, {
								ID: "comp-child-3",
							},
						},
						CVEs: []*model.CVE{},
					},
					"comp-child-1": {
						ID:     "comp-child-1",
						Name:   "Component Child 1",
						CPEs23: []string{"cpe:2.3:a:fake:component:1:child:*:*:*:*:*:*"},
						Parent: &model.Component{
							ID: "comp",
						},
						Children: []*model.Component{},
						CVEs:     []*model.CVE{},
					},
					"comp-child-2": {
						ID:       "comp-child-2",
						Name:     "Component Child 2",
						CPEs23:   []string{"cpe:2.3:a:fake:component:2:child:*:*:*:*:*:*"},
						Parent:   nil,
						Children: []*model.Component{},
						CVEs:     []*model.CVE{},
					},
					"comp-child-3": {
						ID:     "comp-child-3",
						Name:   "Component Child 3",
						CPEs23: []string{"cpe:2.3:a:fake:component:3:child:*:*:*:*:*:*"},
						Parent: &model.Component{
							ID: "comp",
						},
						Children: []*model.Component{},
						CVEs:     []*model.CVE{},
					},
				},
				CompVPIndex: map[string]map[string]struct{}{
					"fake:component": {
						"comp":         {},
						"comp-child-1": {},
						"comp-child-2": {},
						"comp-child-3": {},
					},
				},
				CVEs:       map[string]*model.CVE{},
				CVEVPIndex: map[string]map[string]struct{}{},
			},
			Input: db.UpdateComponentInput{
				ID:     "comp",
				Name:   nil,
				CPEs23: nil,
				Parent: nil,
				Children: []db.UpdateComponentChildInput{
					{
						ID: "comp-child-2",
					}, {
						ID: "comp-child-3",
					},
				},
				CVEs: nil,
			},
			ExpectedErr: nil,
			ExpectedMemory: &db.Memory{
				Components: map[string]*model.Component{
					"comp": {
						ID:     "comp",
						Name:   "Component",
						CPEs23: []string{"cpe:2.3:a:fake:component:*:*:*:*:*:*:*:*"},
						Parent: nil,
						Children: []*model.Component{
							{
								ID: "comp-child-2",
							}, {
								ID: "comp-child-3",
							},
						},
						CVEs: []*model.CVE{},
					},
					"comp-child-1": {
						ID:       "comp-child-1",
						Name:     "Component Child 1",
						CPEs23:   []string{"cpe:2.3:a:fake:component:1:child:*:*:*:*:*:*"},
						Parent:   nil,
						Children: []*model.Component{},
						CVEs:     []*model.CVE{},
					},
					"comp-child-2": {
						ID:     "comp-child-2",
						Name:   "Component Child 2",
						CPEs23: []string{"cpe:2.3:a:fake:component:2:child:*:*:*:*:*:*"},
						Parent: &model.Component{
							ID: "comp",
						},
						Children: []*model.Component{},
						CVEs:     []*model.CVE{},
					},
					"comp-child-3": {
						ID:     "comp-child-3",
						Name:   "Component Child 3",
						CPEs23: []string{"cpe:2.3:a:fake:component:3:child:*:*:*:*:*:*"},
						Parent: &model.Component{
							ID: "comp",
						},
						Children: []*model.Component{},
						CVEs:     []*model.CVE{},
					},
				},
				CompVPIndex: map[string]map[string]struct{}{
					"fake:component": {
						"comp":         {},
						"comp-child-1": {},
						"comp-child-2": {},
						"comp-child-3": {},
					},
				},
				CVEs:       map[string]*model.CVE{},
				CVEVPIndex: map[string]map[string]struct{}{},
			},
		},
		"new-cves": {
			Memory: &db.Memory{
				Components: map[string]*model.Component{
					"comp": {
						ID:       "comp",
						Name:     "Component",
						CPEs23:   []string{"cpe:2.3:a:fake:component:*:*:*:*:*:*:*:*"},
						Parent:   nil,
						Children: []*model.Component{},
						CVEs: []*model.CVE{
							{
								ID: "cve-1",
							}, {
								ID: "cve-3",
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
					},
				},
				CVEVPIndex: map[string]map[string]struct{}{
					"fake:component": {
						"cve-1": {},
						"cve-2": {},
						"cve-3": {},
					},
				},
			},
			Input: db.UpdateComponentInput{
				ID:       "comp",
				Name:     nil,
				CPEs23:   nil,
				Parent:   nil,
				Children: nil,
				CVEs: []db.UpdateComponentCVEsInput{
					{
						ID: "cve-2",
					}, {
						ID: "cve-3",
					},
				},
			},
			ExpectedErr: nil,
			ExpectedMemory: &db.Memory{
				Components: map[string]*model.Component{
					"comp": {
						ID:       "comp",
						Name:     "Component",
						CPEs23:   []string{"cpe:2.3:a:fake:component:*:*:*:*:*:*:*:*"},
						Parent:   nil,
						Children: []*model.Component{},
						CVEs: []*model.CVE{
							{
								ID: "cve-2",
							}, {
								ID: "cve-3",
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
					},
				},
				CVEVPIndex: map[string]map[string]struct{}{
					"fake:component": {
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

			err := tt.Memory.UpdateComponent(tt.Input)

			assert.Equal(tt.ExpectedErr, err)
			assertEqual(tt.ExpectedMemory, tt.Memory, assert)
		})
	}
}

func TestMemoryDeleteComponent(t *testing.T) {
	t.Parallel()

	var tests = map[string]struct {
		Memory         *db.Memory
		Input          db.DeleteComponentInput
		ExpectedErr    error
		ExpectedMemory *db.Memory
	}{
		"unexisting-component": {
			Memory: &db.Memory{
				Components:  map[string]*model.Component{},
				CompVPIndex: map[string]map[string]struct{}{},
				CVEs:        map[string]*model.CVE{},
				CVEVPIndex:  map[string]map[string]struct{}{},
			},
			Input: db.DeleteComponentInput{
				ID: "comp",
			},
			ExpectedErr: &db.ErrNotExist{
				K: db.KeyComponent,
				V: "comp",
			},
			ExpectedMemory: &db.Memory{
				Components:  map[string]*model.Component{},
				CompVPIndex: map[string]map[string]struct{}{},
				CVEs:        map[string]*model.CVE{},
				CVEVPIndex:  map[string]map[string]struct{}{},
			},
		},
		"existing-component": {
			Memory: &db.Memory{
				Components: map[string]*model.Component{
					"comp-parent": {
						ID:     "comp-parent",
						Name:   "Component Parent",
						CPEs23: []string{"cpe:2.3:a:fake:component:*:parent:*:*:*:*:*:*"},
						Parent: nil,
						Children: []*model.Component{
							{
								ID: "comp",
							},
						},
						CVEs: []*model.CVE{},
					},
					"comp": {
						ID:     "comp",
						Name:   "Component",
						CPEs23: []string{"cpe:2.3:a:fake:component\\_goodbye:*:*:*:*:*:*:*:*"},
						Parent: &model.Component{
							ID: "comp-parent",
						},
						Children: []*model.Component{
							{
								ID: "comp-child",
							},
						},
						CVEs: []*model.CVE{
							{
								ID: "cve",
							},
						},
					},
					"comp-child": {
						ID:     "comp-child",
						Name:   "Component Child",
						CPEs23: []string{"cpe:2.3:a:fake:component:*:child:*:*:*:*:*:*"},
						Parent: &model.Component{
							ID: "comp",
						},
						Children: []*model.Component{},
						CVEs:     []*model.CVE{},
					},
				},
				CompVPIndex: map[string]map[string]struct{}{
					"fake:component": {
						"comp-parent": {},
						"comp-child":  {},
					},
					"fake:component\\_goodbye": {
						"comp": {},
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
			ExpectedErr: nil,
			ExpectedMemory: &db.Memory{
				Components: map[string]*model.Component{
					"comp-parent": {
						ID:       "comp-parent",
						Name:     "Component Parent",
						CPEs23:   []string{"cpe:2.3:a:fake:component:*:parent:*:*:*:*:*:*"},
						Parent:   nil,
						Children: []*model.Component{},
						CVEs:     []*model.CVE{},
					},
					"comp-child": {
						ID:       "comp-child",
						Name:     "Component Child",
						CPEs23:   []string{"cpe:2.3:a:fake:component:*:child:*:*:*:*:*:*"},
						Parent:   nil,
						Children: []*model.Component{},
						CVEs:     []*model.CVE{},
					},
				},
				CompVPIndex: map[string]map[string]struct{}{
					"fake:component": {
						"comp-parent": {},
						"comp-child":  {},
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
					},
				},
				CVEVPIndex: map[string]map[string]struct{}{
					"fake:component": {
						"cve": {},
					},
				},
			},
		},
	}

	for testname, tt := range tests {
		t.Run(testname, func(t *testing.T) {
			assert := assert.New(t)

			err := tt.Memory.DeleteComponent(tt.Input)

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
				Components:  map[string]*model.Component{},
				CompVPIndex: map[string]map[string]struct{}{},
				CVEs:        map[string]*model.CVE{},
				CVEVPIndex:  map[string]map[string]struct{}{},
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
				Components:  map[string]*model.Component{},
				CompVPIndex: map[string]map[string]struct{}{},
				CVEs:        map[string]*model.CVE{},
				CVEVPIndex:  map[string]map[string]struct{}{},
			},
		},
		"existing-cve": {
			Memory: &db.Memory{
				Components:  map[string]*model.Component{},
				CompVPIndex: map[string]map[string]struct{}{},
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
					"fake:component": {
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
				Components:  map[string]*model.Component{},
				CompVPIndex: map[string]map[string]struct{}{},
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
					"fake:component": {
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
				Components:  map[string]*model.Component{},
				CompVPIndex: map[string]map[string]struct{}{},
				CVEs:        map[string]*model.CVE{},
				CVEVPIndex:  map[string]map[string]struct{}{},
			},
			Input: db.QueryCVEInput{
				VP: nil,
			},
			ExpectedCVEs: []*model.CVE{},
			ExpectedMemory: &db.Memory{
				Components:  map[string]*model.Component{},
				CompVPIndex: map[string]map[string]struct{}{},
				CVEs:        map[string]*model.CVE{},
				CVEVPIndex:  map[string]map[string]struct{}{},
			},
		},
		"multiple-cves": {
			Memory: &db.Memory{
				Components:  map[string]*model.Component{},
				CompVPIndex: map[string]map[string]struct{}{},
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
			ExpectedMemory: &db.Memory{
				Components:  map[string]*model.Component{},
				CompVPIndex: map[string]map[string]struct{}{},
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
						"cve-1": {},
						"cve-2": {},
					},
				},
			},
		},
		"indexed-cve": {
			Memory: &db.Memory{
				Components:  map[string]*model.Component{},
				CompVPIndex: map[string]map[string]struct{}{},
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
										CPE23:                 "cpe:2.3:a:fake\\_new:component:*:*:*:*:*:*:*:*",
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
						"cve-1": {},
					},
					"fake\\_:component": {
						"cve-2": {},
					},
				},
			},
			Input: db.QueryCVEInput{
				VP: ptr("fake:component"),
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
			ExpectedMemory: &db.Memory{
				Components:  map[string]*model.Component{},
				CompVPIndex: map[string]map[string]struct{}{},
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
										CPE23:                 "cpe:2.3:a:fake\\_new:component:*:*:*:*:*:*:*:*",
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
						"cve-1": {},
					},
					"fake\\_:component": {
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
				Components:  map[string]*model.Component{},
				CompVPIndex: map[string]map[string]struct{}{},
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
								CPE23:                 "cpe:2.3:a:fake:component:*:*:*:*:*:*:*:*",
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
				Components:  map[string]*model.Component{},
				CompVPIndex: map[string]map[string]struct{}{},
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
		},
		"new-cve": {
			Memory: &db.Memory{
				Components:  map[string]*model.Component{},
				CompVPIndex: map[string]map[string]struct{}{},
				CVEs:        map[string]*model.CVE{},
				CVEVPIndex:  map[string]map[string]struct{}{},
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
								CPE23:                 "cpe:2.3:a:fake:component:*:*:*:*:*:*:*:*",
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
			ExpectedErr: nil,
			ExpectedMemory: &db.Memory{
				Components:  map[string]*model.Component{},
				CompVPIndex: map[string]map[string]struct{}{},
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
				Components:  map[string]*model.Component{},
				CompVPIndex: map[string]map[string]struct{}{},
				CVEs:        map[string]*model.CVE{},
				CVEVPIndex:  map[string]map[string]struct{}{},
			},
			Input: db.UpdateCVEInput{
				ID:             "cve",
				Description:    nil,
				LastUpdate:     nil,
				CVSS20Vector:   nil,
				CVSS31Vector:   nil,
				Configurations: nil,
				Components:     nil,
			},
			ExpectedErr: &db.ErrNotExist{
				K: db.KeyCVE,
				V: "cve",
			},
			ExpectedMemory: &db.Memory{
				Components:  map[string]*model.Component{},
				CompVPIndex: map[string]map[string]struct{}{},
				CVEs:        map[string]*model.CVE{},
				CVEVPIndex:  map[string]map[string]struct{}{},
			},
		},
		"component-not-exist": {
			Memory: &db.Memory{
				Components:  map[string]*model.Component{},
				CompVPIndex: map[string]map[string]struct{}{},
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
			Input: db.UpdateCVEInput{
				ID:             "cve",
				Description:    nil,
				LastUpdate:     nil,
				CVSS20Vector:   nil,
				CVSS31Vector:   nil,
				Configurations: nil,
				Components: []db.UpdateCVEComponentInput{
					{
						ID: "comp",
					},
				},
			},
			ExpectedErr: &db.ErrNotExist{
				K: db.KeyComponent,
				V: "comp",
			},
			ExpectedMemory: &db.Memory{
				Components:  map[string]*model.Component{},
				CompVPIndex: map[string]map[string]struct{}{},
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
		},
		"new-description": {
			Memory: &db.Memory{
				Components:  map[string]*model.Component{},
				CompVPIndex: map[string]map[string]struct{}{},
				CVEs: map[string]*model.CVE{
					"cve": {
						ID:              "cve",
						Description:     "CVE in something.",
						PublicationDate: timeParse("2022-02-01T14:30Z"),
						LastUpdate:      timeParse("2022-02-01T14:30Z"),
						CVSS20Vector:    nil,
						CVSS31Vector:    nil,
						Configurations:  []*model.Node{},
						Components:      []*model.Component{},
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
				Components:     nil,
				References:     nil,
			},
			ExpectedErr: nil,
			ExpectedMemory: &db.Memory{
				Components:  map[string]*model.Component{},
				CompVPIndex: map[string]map[string]struct{}{},
				CVEs: map[string]*model.CVE{
					"cve": {
						ID:              "cve",
						Description:     "CVE in something, but new.",
						PublicationDate: timeParse("2022-02-01T14:30Z"),
						LastUpdate:      timeParse("2022-02-01T14:30Z"),
						CVSS20Vector:    nil,
						CVSS31Vector:    nil,
						Configurations:  []*model.Node{},
						Components:      []*model.Component{},
						References:      []*model.Reference{},
					},
				},
				CVEVPIndex: map[string]map[string]struct{}{},
			},
		},
		"new-lastUpdate": {
			Memory: &db.Memory{
				Components:  map[string]*model.Component{},
				CompVPIndex: map[string]map[string]struct{}{},
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
			Input: db.UpdateCVEInput{
				ID:             "cve",
				Description:    nil,
				LastUpdate:     ptr(timeParse("2022-02-01T14:30Z")),
				CVSS20Vector:   nil,
				CVSS31Vector:   nil,
				Configurations: nil,
				Components:     nil,
				References:     nil,
			},
			ExpectedErr: nil,
			ExpectedMemory: &db.Memory{
				Components:  map[string]*model.Component{},
				CompVPIndex: map[string]map[string]struct{}{},
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
		},
		"new-cvss20vector": {
			Memory: &db.Memory{
				Components:  map[string]*model.Component{},
				CompVPIndex: map[string]map[string]struct{}{},
				CVEs: map[string]*model.CVE{
					"cve": {
						ID:              "cve",
						Description:     "CVE in something.",
						PublicationDate: timeParse("2020-02-01T14:30Z"),
						LastUpdate:      timeParse("2020-02-01T14:30Z"),
						CVSS20Vector:    nil,
						CVSS31Vector:    nil,
						Configurations:  []*model.Node{},
						Components:      []*model.Component{},
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
				Components:     nil,
				References:     nil,
			},
			ExpectedErr: nil,
			ExpectedMemory: &db.Memory{
				Components:  map[string]*model.Component{},
				CompVPIndex: map[string]map[string]struct{}{},
				CVEs: map[string]*model.CVE{
					"cve": {
						ID:              "cve",
						Description:     "CVE in something.",
						PublicationDate: timeParse("2020-02-01T14:30Z"),
						LastUpdate:      timeParse("2020-02-01T14:30Z"),
						CVSS20Vector:    ptr("AV:A/AC:H/Au:S/C:P/I:P/A:C"),
						CVSS31Vector:    nil,
						Configurations:  []*model.Node{},
						Components:      []*model.Component{},
						References:      []*model.Reference{},
					},
				},
				CVEVPIndex: map[string]map[string]struct{}{},
			},
		},
		"new-cvss31vector": {
			Memory: &db.Memory{
				Components:  map[string]*model.Component{},
				CompVPIndex: map[string]map[string]struct{}{},
				CVEs: map[string]*model.CVE{
					"cve": {
						ID:              "cve",
						Description:     "CVE in something.",
						PublicationDate: timeParse("2020-02-01T14:30Z"),
						LastUpdate:      timeParse("2020-02-01T14:30Z"),
						CVSS20Vector:    nil,
						CVSS31Vector:    nil,
						Configurations:  []*model.Node{},
						Components:      []*model.Component{},
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
				Components:     nil,
				References:     nil,
			},
			ExpectedErr: nil,
			ExpectedMemory: &db.Memory{
				Components:  map[string]*model.Component{},
				CompVPIndex: map[string]map[string]struct{}{},
				CVEs: map[string]*model.CVE{
					"cve": {
						ID:              "cve",
						Description:     "CVE in something.",
						PublicationDate: timeParse("2020-02-01T14:30Z"),
						LastUpdate:      timeParse("2020-02-01T14:30Z"),
						CVSS20Vector:    nil,
						CVSS31Vector:    ptr("CVSS:3.1/AV:A/AC:H/PR:L/UI:N/S:C/C:L/I:L/A:H"),
						Configurations:  []*model.Node{},
						Components:      []*model.Component{},
						References:      []*model.Reference{},
					},
				},
				CVEVPIndex: map[string]map[string]struct{}{},
			},
		},
		"new-configurations": {
			Memory: &db.Memory{
				Components:  map[string]*model.Component{},
				CompVPIndex: map[string]map[string]struct{}{},
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
										CPE23:                 "cpe:2.3:a:fake:component:*:*:*:*:*:*:*:*",
										VersionStartIncluding: nil,
										VersionStartExcluding: nil,
										VersionEndIncluding:   nil,
										VersionEndExcluding:   nil,
									}, {
										Vulnerable:            true,
										CPE23:                 "cpe:2.3:a:fake\\_old:component:*:*:*:*:*:*:*:*",
										VersionStartIncluding: nil,
										VersionStartExcluding: ptr("3.4.5"),
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
					"fake\\_old:component": {
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
								CPE23:                 "cpe:2.3:a:fake:component:*:*:*:*:*:*:*:*",
								VersionStartIncluding: nil,
								VersionStartExcluding: nil,
								VersionEndIncluding:   nil,
								VersionEndExcluding:   nil,
							}, {
								Vulnerable:            false,
								CPE23:                 "cpe:2.3:a:fake\\_new:component:*:*:*:*:*:*:*:*",
								VersionStartIncluding: nil,
								VersionStartExcluding: nil,
								VersionEndIncluding:   nil,
								VersionEndExcluding:   ptr("1.0.0"),
							},
						},
					},
				},
				Components: nil,
				References: nil,
			},
			ExpectedErr: nil,
			ExpectedMemory: &db.Memory{
				Components:  map[string]*model.Component{},
				CompVPIndex: map[string]map[string]struct{}{},
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
										CPE23:                 "cpe:2.3:a:fake:component:*:*:*:*:*:*:*:*",
										VersionStartIncluding: nil,
										VersionStartExcluding: nil,
										VersionEndIncluding:   nil,
										VersionEndExcluding:   nil,
									}, {
										Vulnerable:            false,
										CPE23:                 "cpe:2.3:a:fake\\_new:component:*:*:*:*:*:*:*:*",
										VersionStartIncluding: nil,
										VersionStartExcluding: nil,
										VersionEndIncluding:   nil,
										VersionEndExcluding:   ptr("1.0.0"),
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
					"fake\\_new:component": {
						"cve": {},
					},
				},
			},
		},
		"new-components": {
			Memory: &db.Memory{
				Components: map[string]*model.Component{
					"comp-1": {
						ID:       "comp-1",
						Name:     "Component 1",
						CPEs23:   []string{"cpe:2.3:a:fake:component:1:*:*:*:*:*:*:*"},
						Parent:   nil,
						Children: []*model.Component{},
						CVEs: []*model.CVE{
							{
								ID: "cve",
							},
						},
					},
					"comp-2": {
						ID:       "comp-2",
						Name:     "Component 2",
						CPEs23:   []string{"cpe:2.3:a:fake:component:2:*:*:*:*:*:*:*"},
						Parent:   nil,
						Children: []*model.Component{},
						CVEs:     []*model.CVE{},
					},
					"comp-3": {
						ID:       "comp-3",
						Name:     "Component 3",
						CPEs23:   []string{"cpe:2.3:a:fake:component:3:*:*:*:*:*:*:*"},
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
						"comp-1": {},
						"comp-2": {},
						"comp-3": {},
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
								ID: "comp-1",
							}, {
								ID: "comp-3",
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
			Input: db.UpdateCVEInput{
				ID:             "cve",
				Description:    nil,
				LastUpdate:     nil,
				CVSS20Vector:   nil,
				CVSS31Vector:   nil,
				Configurations: nil,
				Components: []db.UpdateCVEComponentInput{
					{
						ID: "comp-2",
					}, {
						ID: "comp-3",
					},
				},
				References: nil,
			},
			ExpectedErr: nil,
			ExpectedMemory: &db.Memory{
				Components: map[string]*model.Component{
					"comp-1": {
						ID:       "comp-1",
						Name:     "Component 1",
						CPEs23:   []string{"cpe:2.3:a:fake:component:1:*:*:*:*:*:*:*"},
						Parent:   nil,
						Children: []*model.Component{},
						CVEs:     []*model.CVE{},
					},
					"comp-2": {
						ID:       "comp-2",
						Name:     "Component 2",
						CPEs23:   []string{"cpe:2.3:a:fake:component:2:*:*:*:*:*:*:*"},
						Parent:   nil,
						Children: []*model.Component{},
						CVEs: []*model.CVE{
							{
								ID: "cve",
							},
						},
					},
					"comp-3": {
						ID:       "comp-3",
						Name:     "Component 3",
						CPEs23:   []string{"cpe:2.3:a:fake:component:3:*:*:*:*:*:*:*"},
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
						"comp-1": {},
						"comp-2": {},
						"comp-3": {},
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
								ID: "comp-2",
							}, {
								ID: "comp-3",
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
		},
		"new-references": {
			Memory: &db.Memory{
				Components:  map[string]*model.Component{},
				CompVPIndex: map[string]map[string]struct{}{},
				CVEs: map[string]*model.CVE{
					"cve": {
						ID:              "cve",
						Description:     "",
						PublicationDate: timeParse("2020-02-01T14:30Z"),
						LastUpdate:      timeParse("2020-02-01T14:30Z"),
						CVSS20Vector:    nil,
						CVSS31Vector:    nil,
						Configurations:  []*model.Node{},
						Components:      []*model.Component{},
						References: []*model.Reference{
							{
								URL:       "https://example.com",
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
				Components:     nil,
				References: []db.UpdateCVEReferencesInput{
					{
						URL:       "https://new-example.com",
						Refsource: "MISC",
						Tags:      []string{"Exploit", "Patch"},
					},
				},
			},
			ExpectedErr: nil,
			ExpectedMemory: &db.Memory{
				Components:  map[string]*model.Component{},
				CompVPIndex: map[string]map[string]struct{}{},
				CVEs: map[string]*model.CVE{
					"cve": {
						ID:              "cve",
						Description:     "",
						PublicationDate: timeParse("2020-02-01T14:30Z"),
						LastUpdate:      timeParse("2020-02-01T14:30Z"),
						CVSS20Vector:    nil,
						CVSS31Vector:    nil,
						Configurations:  []*model.Node{},
						Components:      []*model.Component{},
						References: []*model.Reference{
							{
								URL:       "https://new-example.com",
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
				Components:  map[string]*model.Component{},
				CompVPIndex: map[string]map[string]struct{}{},
				CVEs:        map[string]*model.CVE{},
				CVEVPIndex:  map[string]map[string]struct{}{},
			},
			Input: db.DeleteCVEInput{
				ID: "cve",
			},
			ExpectedErr: &db.ErrNotExist{
				K: db.KeyCVE,
				V: "cve",
			},
			ExpectedMemory: &db.Memory{
				Components:  map[string]*model.Component{},
				CompVPIndex: map[string]map[string]struct{}{},
				CVEs:        map[string]*model.CVE{},
				CVEVPIndex:  map[string]map[string]struct{}{},
			},
		},
		"existing-cve": {
			Memory: &db.Memory{
				Components: map[string]*model.Component{
					"comp": {
						ID:       "comp",
						Name:     "Component",
						CPEs23:   []string{"cpe:2.3:a:fake:component:*:*:*:*:*:*:*:*"},
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
			Input: db.DeleteCVEInput{
				ID: "cve",
			},
			ExpectedErr: nil,
			ExpectedMemory: &db.Memory{
				Components: map[string]*model.Component{
					"comp": {
						ID:       "comp",
						Name:     "Component",
						CPEs23:   []string{"cpe:2.3:a:fake:component:*:*:*:*:*:*:*:*"},
						Parent:   nil,
						Children: []*model.Component{},
						CVEs:     []*model.CVE{},
					},
				},
				CompVPIndex: map[string]map[string]struct{}{
					"fake:component": {
						"comp": {},
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

func TestGetComponentCVEs(t *testing.T) {
	t.Parallel()

	var tests = map[string]struct {
		Memory         *db.Memory
		Component      *model.Component
		ExpectedCVEs   []*model.CVE
		ExpectedMemory *db.Memory
	}{
		"no-cves": {
			Memory: &db.Memory{
				Components: map[string]*model.Component{
					"comp": {
						ID:       "comp",
						Name:     "Component",
						CPEs23:   []string{},
						Parent:   nil,
						Children: []*model.Component{},
						CVEs:     []*model.CVE{},
					},
				},
				CompVPIndex: map[string]map[string]struct{}{},
				CVEs:        map[string]*model.CVE{},
				CVEVPIndex:  map[string]map[string]struct{}{},
			},
			Component: &model.Component{
				ID:       "comp",
				Name:     "Component",
				CPEs23:   []string{},
				Parent:   nil,
				Children: []*model.Component{},
				CVEs:     []*model.CVE{},
			},
			ExpectedCVEs: []*model.CVE{},
			ExpectedMemory: &db.Memory{
				Components: map[string]*model.Component{
					"comp": {
						ID:       "comp",
						Name:     "Component",
						CPEs23:   []string{},
						Parent:   nil,
						Children: []*model.Component{},
						CVEs:     []*model.CVE{},
					},
				},
				CompVPIndex: map[string]map[string]struct{}{},
				CVEs:        map[string]*model.CVE{},
				CVEVPIndex:  map[string]map[string]struct{}{},
			},
		},
		"multiple-cves": {
			Memory: &db.Memory{
				Components: map[string]*model.Component{
					"comp": {
						ID:       "comp",
						Name:     "Component",
						CPEs23:   []string{},
						Parent:   nil,
						Children: []*model.Component{},
						CVEs: []*model.CVE{
							{
								ID: "cve-1",
							}, {
								ID: "cve-2",
							},
						},
					},
				},
				CompVPIndex: map[string]map[string]struct{}{},
				CVEs: map[string]*model.CVE{
					"cve-1": {
						ID:              "cve-1",
						Description:     "CVE example 1",
						PublicationDate: timeParse("2020-01-02T14:00Z"),
						LastUpdate:      timeParse("2020-01-02T14:00Z"),
						CVSS20Vector:    nil,
						CVSS31Vector:    nil,
						Configurations:  []*model.Node{},
						Components: []*model.Component{
							{
								ID: "comp",
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
						Components: []*model.Component{
							{
								ID: "comp",
							},
						},
						References: []*model.Reference{},
					},
				},
				CVEVPIndex: map[string]map[string]struct{}{},
			},
			Component: &model.Component{
				ID:       "comp",
				Name:     "Component",
				CPEs23:   []string{},
				Parent:   nil,
				Children: []*model.Component{},
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
					Components: []*model.Component{
						{
							ID: "comp",
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
					Components: []*model.Component{
						{
							ID: "comp",
						},
					},
					References: []*model.Reference{},
				},
			},
			ExpectedMemory: &db.Memory{
				Components: map[string]*model.Component{
					"comp": {
						ID:       "comp",
						Name:     "Component",
						CPEs23:   []string{},
						Parent:   nil,
						Children: []*model.Component{},
						CVEs: []*model.CVE{
							{
								ID: "cve-1",
							}, {
								ID: "cve-2",
							},
						},
					},
				},
				CompVPIndex: map[string]map[string]struct{}{},
				CVEs: map[string]*model.CVE{
					"cve-1": {
						ID:              "cve-1",
						Description:     "CVE example 1",
						PublicationDate: timeParse("2020-01-02T14:00Z"),
						LastUpdate:      timeParse("2020-01-02T14:00Z"),
						CVSS20Vector:    nil,
						CVSS31Vector:    nil,
						Configurations:  []*model.Node{},
						Components: []*model.Component{
							{
								ID: "comp",
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
						Components: []*model.Component{
							{
								ID: "comp",
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

			cves := tt.Memory.GetComponentCVEs(tt.Component)

			assert.ElementsMatch(tt.ExpectedCVEs, cves)

			// Check return can't be modified
			for i := 0; i < len(cves); i++ {
				alter(cves[i])
			}
			assertEqual(tt.ExpectedMemory, tt.Memory, assert)
		})
	}
}

func TestGetCVEComponents(t *testing.T) {
	t.Parallel()

	var tests = map[string]struct {
		Memory             *db.Memory
		CVE                *model.CVE
		ExpectedComponents []*model.Component
		ExpectedMemory     *db.Memory
	}{
		"no-comps": {
			Memory: &db.Memory{
				Components:  map[string]*model.Component{},
				CompVPIndex: map[string]map[string]struct{}{},
				CVEs: map[string]*model.CVE{
					"cve": {
						ID:              "cve",
						Description:     "CVE example",
						PublicationDate: timeParse("2020-01-02T14:00Z"),
						LastUpdate:      timeParse("2020-01-02T14:00Z"),
						CVSS20Vector:    nil,
						CVSS31Vector:    nil,
						Configurations:  []*model.Node{},
						Components:      []*model.Component{},
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
				Components:      []*model.Component{},
			},
			ExpectedComponents: []*model.Component{},
			ExpectedMemory: &db.Memory{
				Components:  map[string]*model.Component{},
				CompVPIndex: map[string]map[string]struct{}{},
				CVEs: map[string]*model.CVE{
					"cve": {
						ID:              "cve",
						Description:     "CVE example",
						PublicationDate: timeParse("2020-01-02T14:00Z"),
						LastUpdate:      timeParse("2020-01-02T14:00Z"),
						CVSS20Vector:    nil,
						CVSS31Vector:    nil,
						Configurations:  []*model.Node{},
						Components:      []*model.Component{},
					},
				},
				CVEVPIndex: map[string]map[string]struct{}{},
			},
		},
		"multiple-comps": {
			Memory: &db.Memory{
				Components: map[string]*model.Component{
					"comp-1": {
						ID:       "comp-1",
						Name:     "Component 1",
						CPEs23:   []string{},
						Parent:   nil,
						Children: []*model.Component{},
						CVEs: []*model.CVE{
							{
								ID: "cve",
							},
						},
					},
					"comp-2": {
						ID:       "comp-2",
						Name:     "Component 2",
						CPEs23:   []string{},
						Parent:   nil,
						Children: []*model.Component{},
						CVEs: []*model.CVE{
							{
								ID: "cve",
							},
						},
					},
				},
				CompVPIndex: map[string]map[string]struct{}{},
				CVEs: map[string]*model.CVE{
					"cve": {
						ID:              "cve",
						Description:     "CVE example",
						PublicationDate: timeParse("2020-01-02T14:00Z"),
						LastUpdate:      timeParse("2020-01-02T14:00Z"),
						CVSS20Vector:    nil,
						CVSS31Vector:    nil,
						Configurations:  []*model.Node{},
						Components: []*model.Component{
							{
								ID: "comp-1",
							}, {
								ID: "comp-2",
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
				Components: []*model.Component{
					{
						ID: "comp-1",
					}, {
						ID: "comp-2",
					},
				},
				References: []*model.Reference{},
			},
			ExpectedComponents: []*model.Component{
				{
					ID:       "comp-1",
					Name:     "Component 1",
					CPEs23:   []string{},
					Parent:   nil,
					Children: []*model.Component{},
					CVEs: []*model.CVE{
						{
							ID: "cve",
						},
					},
				}, {
					ID:       "comp-2",
					Name:     "Component 2",
					CPEs23:   []string{},
					Parent:   nil,
					Children: []*model.Component{},
					CVEs: []*model.CVE{
						{
							ID: "cve",
						},
					},
				},
			},
			ExpectedMemory: &db.Memory{
				Components: map[string]*model.Component{
					"comp-1": {
						ID:       "comp-1",
						Name:     "Component 1",
						CPEs23:   []string{},
						Parent:   nil,
						Children: []*model.Component{},
						CVEs: []*model.CVE{
							{
								ID: "cve",
							},
						},
					},
					"comp-2": {
						ID:       "comp-2",
						Name:     "Component 2",
						CPEs23:   []string{},
						Parent:   nil,
						Children: []*model.Component{},
						CVEs: []*model.CVE{
							{
								ID: "cve",
							},
						},
					},
				},
				CompVPIndex: map[string]map[string]struct{}{},
				CVEs: map[string]*model.CVE{
					"cve": {
						ID:              "cve",
						Description:     "CVE example",
						PublicationDate: timeParse("2020-01-02T14:00Z"),
						LastUpdate:      timeParse("2020-01-02T14:00Z"),
						CVSS20Vector:    nil,
						CVSS31Vector:    nil,
						Configurations:  []*model.Node{},
						Components: []*model.Component{
							{
								ID: "comp-1",
							}, {
								ID: "comp-2",
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

			comps := tt.Memory.GetCVEComponents(tt.CVE)

			assert.ElementsMatch(tt.ExpectedComponents, comps)

			// Check return can't be modified
			for i := 0; i < len(comps); i++ {
				alter(comps[i])
			}
			assertEqual(tt.ExpectedMemory, tt.Memory, assert)
		})
	}
}
