package api

import (
	"github.com/google/uuid"
	"github.com/graphql-go/graphql"
	apidb "github.com/pandatix/cvedetect/api/db"
	"github.com/pandatix/cvedetect/api/mutation"
	"github.com/pandatix/cvedetect/api/object"
	"github.com/pandatix/cvedetect/db"
)

var MutationObject = graphql.NewObject(graphql.ObjectConfig{
	Name: "Mutation",
	Fields: graphql.Fields{
		"addAsset": {
			Description: "Add a Asset.",
			Type:        graphql.NewNonNull(object.Asset),
			Args: graphql.FieldConfigArgument{
				"input": {
					Type: graphql.NewNonNull(object.AddAssetInput),
				},
			},
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				input := db.AddAssetInput{}
				Cast(p.Args["input"], &input)

				input.ID = uuid.NewString()

				return mutation.AddAsset(apidb.Mem, input)
			},
		},
		"updateAsset": {
			Description: "Update a Asset.",
			Type:        graphql.NewNonNull(object.Asset),
			Args: graphql.FieldConfigArgument{
				"input": {
					Type: graphql.NewNonNull(object.UpdateAssetInput),
				},
			},
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				input := db.UpdateAssetInput{}
				Cast(p.Args["input"], &input)
				return mutation.UpdateAsset(apidb.Mem, input)
			},
		},
		"deleteAsset": {
			Description: "Delete a Asset.",
			Type:        graphql.NewNonNull(object.Asset),
			Args: graphql.FieldConfigArgument{
				"input": {
					Type: graphql.NewNonNull(object.DeleteAssetInput),
				},
			},
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				input := db.DeleteAssetInput{}
				Cast(p.Args["input"], &input)
				return mutation.DeleteAsset(apidb.Mem, input)
			},
		},
		"addCVE": {
			Description: "Add a CVE.",
			Type:        graphql.NewNonNull(object.CVE),
			Args: graphql.FieldConfigArgument{
				"input": {
					Type: graphql.NewNonNull(object.AddCVEInput),
				},
			},
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				input := db.AddCVEInput{}
				Cast(p.Args["input"], &input)
				return mutation.AddCVE(apidb.Mem, input)
			},
		},
		"updateCVE": {
			Description: "Update a CVE.",
			Type:        graphql.NewNonNull(object.CVE),
			Args: graphql.FieldConfigArgument{
				"input": {
					Type: graphql.NewNonNull(object.UpdateCVEInput),
				},
			},
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				input := db.UpdateCVEInput{}
				Cast(p.Args["input"], &input)
				return mutation.UpdateCVE(apidb.Mem, input)
			},
		},
		"deleteCVE": {
			Description: "Delete a CVE.",
			Type:        graphql.NewNonNull(object.CVE),
			Args: graphql.FieldConfigArgument{
				"input": {
					Type: graphql.NewNonNull(object.DeleteCVEInput),
				},
			},
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				input := db.DeleteCVEInput{}
				Cast(p.Args["input"], &input)
				return mutation.DeleteCVE(apidb.Mem, input)
			},
		},
	},
})
