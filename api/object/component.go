package object

import (
	"github.com/graphql-go/graphql"
	apidb "github.com/pandatix/cvedetect/api/db"
	"github.com/pandatix/cvedetect/api/scalar"
	"github.com/pandatix/cvedetect/model"
)

var Component = graphql.NewObject(graphql.ObjectConfig{
	Name:        "Component",
	Description: "Component is an IT component as defined by NIST-IR 7695.",
	Fields: graphql.Fields{
		"id": {
			Type: graphql.NewNonNull(graphql.String),
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				if comp, ok := p.Source.(*model.Component); ok {
					return comp.ID, nil
				}
				return nil, nil
			},
		},
		"name": {
			Type: graphql.NewNonNull(graphql.String),
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				if comp, ok := p.Source.(*model.Component); ok {
					return comp.Name, nil
				}
				return nil, nil
			},
		},
		"cpes23": {
			Type: graphql.NewNonNull(&graphql.List{
				OfType: graphql.NewNonNull(scalar.CPE23),
			}),
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				if comp, ok := p.Source.(*model.Component); ok {
					return comp.CPEs23, nil
				}
				return nil, nil
			},
		},
		"cves": {
			Type: graphql.NewNonNull(&graphql.List{
				OfType: graphql.NewNonNull(CVE),
			}),
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				if comp, ok := p.Source.(*model.Component); ok {
					return apidb.Mem.GetComponentCVEs(comp), nil
				}
				return nil, nil
			},
		},
	},
})

var GetComponentInput = graphql.NewInputObject(graphql.InputObjectConfig{
	Name: "GetComponentInput",
	Fields: graphql.InputObjectConfigFieldMap{
		"id": {
			Type: graphql.NewNonNull(graphql.String),
		},
	},
})

var QueryComponentsInput = graphql.NewInputObject(graphql.InputObjectConfig{
	Name: "QueryComponentsInput",
	Fields: graphql.InputObjectConfigFieldMap{
		"vp": {
			Type:        graphql.String,
			Description: "\"vendor:product\" couple to look for.",
		},
	},
})

var AddComponentInput = graphql.NewInputObject(graphql.InputObjectConfig{
	Name: "AddComponentInput",
	Fields: graphql.InputObjectConfigFieldMap{
		"name": {
			Type: graphql.NewNonNull(graphql.String),
		},
		"cpes23": {
			Type: graphql.NewNonNull(&graphql.List{
				OfType: graphql.NewNonNull(scalar.CPE23),
			}),
		},
		"parent": {
			Type: AddComponentParentInput,
		},
		"children": {
			Type: &graphql.List{
				OfType: graphql.NewNonNull(AddComponentChildInput),
			},
		},
	},
})

var AddComponentParentInput = graphql.NewInputObject(graphql.InputObjectConfig{
	Name: "AddComponentParentInput",
	Fields: graphql.InputObjectConfigFieldMap{
		"id": {
			Type: graphql.NewNonNull(graphql.String),
		},
	},
})

var AddComponentChildInput = graphql.NewInputObject(graphql.InputObjectConfig{
	Name: "AddComponentChildInput",
	Fields: graphql.InputObjectConfigFieldMap{
		"id": {
			Type: graphql.NewNonNull(graphql.String),
		},
	},
})

var UpdateComponentInput = graphql.NewInputObject(graphql.InputObjectConfig{
	Name: "UpdateComponentInput",
	Fields: graphql.InputObjectConfigFieldMap{
		"id": {
			Type: graphql.NewNonNull(graphql.String),
		},
		"name": {
			Type: graphql.String,
		},
		"cpes23": {
			Type: &graphql.List{
				OfType: graphql.NewNonNull(scalar.CPE23),
			},
		},
		"parent": {
			Type: UpdateComponentParentInput,
		},
		"children": {
			Type: &graphql.List{
				OfType: graphql.NewNonNull(UpdateComponentChildInput),
			},
		},
	},
})

var UpdateComponentParentInput = graphql.NewInputObject(graphql.InputObjectConfig{
	Name: "UpdateComponentParentInput",
	Fields: graphql.InputObjectConfigFieldMap{
		"id": {
			Type: graphql.NewNonNull(graphql.String),
		},
	},
})

var UpdateComponentChildInput = graphql.NewInputObject(graphql.InputObjectConfig{
	Name: "UpdateComponentChildInput",
	Fields: graphql.InputObjectConfigFieldMap{
		"id": {
			Type: graphql.NewNonNull(graphql.String),
		},
	},
})

var DeleteComponentInput = graphql.NewInputObject(graphql.InputObjectConfig{
	Name: "DeleteComponentInput",
	Fields: graphql.InputObjectConfigFieldMap{
		"id": {
			Type: graphql.NewNonNull(graphql.String),
		},
	},
})

func init() {
	Component.AddFieldConfig("chilren", &graphql.Field{
		Type: graphql.NewNonNull(&graphql.List{
			OfType: graphql.NewNonNull(Component),
		}),
		Resolve: func(p graphql.ResolveParams) (interface{}, error) {
			if comp, ok := p.Source.(*model.Component); ok {
				return comp.Children, nil
			}
			return nil, nil
		},
	})
	Component.AddFieldConfig("parent", &graphql.Field{
		Type: Component,
		Resolve: func(p graphql.ResolveParams) (interface{}, error) {
			if comp, ok := p.Source.(*model.Component); ok {
				return comp.Parent, nil
			}
			return nil, nil
		},
	})
}
