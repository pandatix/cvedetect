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
		"dependents": {
			Type: &graphql.List{
				OfType: graphql.NewNonNull(AddAssetDepInput),
			},
		},
		"dependencies": {
			Type: &graphql.List{
				OfType: graphql.NewNonNull(AddAssetDepInput),
			},
		},
	},
})

var AddAssetDepInput = graphql.NewInputObject(graphql.InputObjectConfig{
	Name: "AddAssetDepInput",
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
		"dependents": {
			Type: &graphql.List{
				OfType: graphql.NewNonNull(UpdateAssetDepInput),
			},
		},
		"dependencies": {
			Type: &graphql.List{
				OfType: graphql.NewNonNull(UpdateAssetDepInput),
			},
		},
	},
})

var UpdateAssetDepInput = graphql.NewInputObject(graphql.InputObjectConfig{
	Name: "UpdateAssetDepInput",
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
	Asset.AddFieldConfig("dependents", &graphql.Field{
		Type: graphql.NewNonNull(&graphql.List{
			OfType: graphql.NewNonNull(Asset),
		}),
		Resolve: func(p graphql.ResolveParams) (interface{}, error) {
			if asset, ok := p.Source.(*model.Asset); ok {
				return asset.Dependents, nil
			}
			return nil, nil
		},
	})
	Asset.AddFieldConfig("dependencies", &graphql.Field{
		Type: graphql.NewNonNull(&graphql.List{
			OfType: graphql.NewNonNull(Asset),
		}),
		Resolve: func(p graphql.ResolveParams) (interface{}, error) {
			if asset, ok := p.Source.(*model.Asset); ok {
				return asset.Dependencies, nil
			}
			return nil, nil
		},
	})
}
