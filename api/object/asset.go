package object

import (
	"github.com/graphql-go/graphql"
	apidb "github.com/pandatix/cvedetect/api/db"
	"github.com/pandatix/cvedetect/api/scalar"
	"github.com/pandatix/cvedetect/model"
)

var Asset = graphql.NewObject(graphql.ObjectConfig{
	Name:        "Asset",
	Description: "Asset could represent anything in an IT system. It could be also named \"Component\" as its achieved by the NIST-IR 7695.",
	Fields: graphql.Fields{
		"id": {
			Type: graphql.NewNonNull(graphql.String),
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				if asset, ok := p.Source.(*model.Asset); ok {
					return asset.ID, nil
				}
				return nil, nil
			},
		},
		"name": {
			Type: graphql.NewNonNull(graphql.String),
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				if asset, ok := p.Source.(*model.Asset); ok {
					return asset.Name, nil
				}
				return nil, nil
			},
		},
		"cpe23": {
			Type: graphql.NewNonNull(scalar.CPE23),
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				if asset, ok := p.Source.(*model.Asset); ok {
					return asset.CPE23, nil
				}
				return nil, nil
			},
		},
		"cves": {
			Type: graphql.NewNonNull(&graphql.List{
				OfType: graphql.NewNonNull(CVE),
			}),
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				if asset, ok := p.Source.(*model.Asset); ok {
					return apidb.Mem.GetAssetCVEs(asset), nil
				}
				return nil, nil
			},
		},
	},
})

var GetAssetInput = graphql.NewInputObject(graphql.InputObjectConfig{
	Name: "GetAssetInput",
	Fields: graphql.InputObjectConfigFieldMap{
		"id": {
			Type: graphql.NewNonNull(graphql.String),
		},
	},
})

var QueryAssetsInput = graphql.NewInputObject(graphql.InputObjectConfig{
	Name: "QueryAssetsInput",
	Fields: graphql.InputObjectConfigFieldMap{
		"vp": {
			Type:        graphql.String,
			Description: "\"vendor:product\" couple to look for.",
		},
	},
})

var AddAssetInput = graphql.NewInputObject(graphql.InputObjectConfig{
	Name: "AddAssetInput",
	Fields: graphql.InputObjectConfigFieldMap{
		"name": {
			Type: graphql.NewNonNull(graphql.String),
		},
		"cpe23": {
			Type: graphql.NewNonNull(scalar.CPE23),
		},
		"parents": {
			Type: &graphql.List{
				OfType: graphql.NewNonNull(AddAssetParentInput),
			},
		},
		"children": {
			Type: &graphql.List{
				OfType: graphql.NewNonNull(AddAssetChildInput),
			},
		},
	},
})

var AddAssetParentInput = graphql.NewInputObject(graphql.InputObjectConfig{
	Name: "AddAssetParentInput",
	Fields: graphql.InputObjectConfigFieldMap{
		"id": {
			Type: graphql.NewNonNull(graphql.String),
		},
	},
})

var AddAssetChildInput = graphql.NewInputObject(graphql.InputObjectConfig{
	Name: "AddAssetChildInput",
	Fields: graphql.InputObjectConfigFieldMap{
		"id": {
			Type: graphql.NewNonNull(graphql.String),
		},
	},
})

var UpdateAssetInput = graphql.NewInputObject(graphql.InputObjectConfig{
	Name: "UpdateAssetInput",
	Fields: graphql.InputObjectConfigFieldMap{
		"id": {
			Type: graphql.NewNonNull(graphql.String),
		},
		"name": {
			Type: graphql.String,
		},
		"cpe23": {
			Type: scalar.CPE23,
		},
		"parents": {
			Type: &graphql.List{
				OfType: graphql.NewNonNull(UpdateAssetParentInput),
			},
		},
		"children": {
			Type: &graphql.List{
				OfType: graphql.NewNonNull(UpdateAssetChildInput),
			},
		},
	},
})

var UpdateAssetParentInput = graphql.NewInputObject(graphql.InputObjectConfig{
	Name: "UpdateAssetParentInput",
	Fields: graphql.InputObjectConfigFieldMap{
		"id": {
			Type: graphql.NewNonNull(graphql.String),
		},
	},
})

var UpdateAssetChildInput = graphql.NewInputObject(graphql.InputObjectConfig{
	Name: "UpdateAssetChildInput",
	Fields: graphql.InputObjectConfigFieldMap{
		"id": {
			Type: graphql.NewNonNull(graphql.String),
		},
	},
})

var DeleteAssetInput = graphql.NewInputObject(graphql.InputObjectConfig{
	Name: "DeleteAssetInput",
	Fields: graphql.InputObjectConfigFieldMap{
		"id": {
			Type: graphql.NewNonNull(graphql.String),
		},
	},
})

func init() {
	Asset.AddFieldConfig("chilren", &graphql.Field{
		Type: graphql.NewNonNull(&graphql.List{
			OfType: graphql.NewNonNull(Asset),
		}),
		Resolve: func(p graphql.ResolveParams) (interface{}, error) {
			if asset, ok := p.Source.(*model.Asset); ok {
				return asset.Children, nil
			}
			return nil, nil
		},
	})
	Asset.AddFieldConfig("parents", &graphql.Field{
		Type: graphql.NewNonNull(&graphql.List{
			OfType: graphql.NewNonNull(Asset),
		}),
		Resolve: func(p graphql.ResolveParams) (interface{}, error) {
			if asset, ok := p.Source.(*model.Asset); ok {
				return asset.Parents, nil
			}
			return nil, nil
		},
	})
}
