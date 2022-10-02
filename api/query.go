package api

import (
	"github.com/graphql-go/graphql"
	apidb "github.com/pandatix/cvedetect/api/db"
	"github.com/pandatix/cvedetect/api/object"
	"github.com/pandatix/cvedetect/api/query"
	"github.com/pandatix/cvedetect/db"
)

var QueryObject = graphql.NewObject(graphql.ObjectConfig{
	Name: "Query",
	Fields: graphql.Fields{
		"getAsset": {
			Description: "Get a specific Asset.",
			Type:        object.Asset,
			Args: graphql.FieldConfigArgument{
				"input": {
					Type: graphql.NewNonNull(object.GetAssetInput),
				},
			},
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				input := db.GetAssetInput{}
				Cast(p.Args["input"], &input)
				return query.GetAsset(apidb.Mem, input)
			},
		},
		"queryAssets": {
			Description: "Query a list of Asset.",
			Type: graphql.NewNonNull(&graphql.List{
				OfType: graphql.NewNonNull(object.Asset),
			}),
			Args: graphql.FieldConfigArgument{
				"input": {
					Type: graphql.NewNonNull(object.QueryAssetsInput),
				},
			},
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				input := db.QueryAssetInput{}
				Cast(p.Args["input"], &input)
				return query.QueryAssets(apidb.Mem, input)
			},
		},
		"getCVE": {
			Description: "Get a specific CVE.",
			Type:        object.CVE,
			Args: graphql.FieldConfigArgument{
				"input": {
					Type: graphql.NewNonNull(object.GetCVEInput),
				},
			},
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				input := db.GetCVEInput{}
				Cast(p.Args["input"], &input)
				return query.GetCVE(apidb.Mem, input)
			},
		},
		"queryCVEs": {
			Description: "Query a list of CVE.",
			Type: graphql.NewNonNull(&graphql.List{
				OfType: graphql.NewNonNull(object.CVE),
			}),
			Args: graphql.FieldConfigArgument{
				"input": {
					Type: graphql.NewNonNull(object.QueryCVEsInput),
				},
			},
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				input := db.QueryCVEInput{}
				Cast(p.Args["input"], &input)
				return query.QueryCVEs(apidb.Mem, input)
			},
		},
	},
})
