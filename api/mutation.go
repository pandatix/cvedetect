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
		"addComponent": {
			Description: "Add a Component.",
			Type:        graphql.NewNonNull(object.Component),
			Args: graphql.FieldConfigArgument{
				"input": {
					Type: graphql.NewNonNull(object.AddComponentInput),
				},
			},
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				input := db.AddComponentInput{}
				Cast(p.Args["input"], &input)

				input.ID = uuid.NewString()

				return mutation.AddComponent(apidb.Mem, input)
			},
		},
		"updateComponent": {
			Description: "Update a Component.",
			Type:        graphql.NewNonNull(object.Component),
			Args: graphql.FieldConfigArgument{
				"input": {
					Type: graphql.NewNonNull(object.UpdateComponentInput),
				},
			},
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				input := db.UpdateComponentInput{}
				Cast(p.Args["input"], &input)
				return mutation.UpdateComponent(apidb.Mem, input)
			},
		},
		"deleteComponent": {
			Description: "Delete a Component.",
			Type:        graphql.NewNonNull(object.Component),
			Args: graphql.FieldConfigArgument{
				"input": {
					Type: graphql.NewNonNull(object.DeleteComponentInput),
				},
			},
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				input := db.DeleteComponentInput{}
				Cast(p.Args["input"], &input)
				return mutation.DeleteComponent(apidb.Mem, input)
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
