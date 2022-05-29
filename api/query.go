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
		"getComponent": {
			Description: "Get a specific Component.",
			Type:        object.Component,
			Args: graphql.FieldConfigArgument{
				"input": {
					Type: graphql.NewNonNull(object.GetComponentInput),
				},
			},
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				input := db.GetComponentInput{}
				Cast(p.Args["input"], &input)
				return query.GetComponent(apidb.Mem, input)
			},
		},
		"queryComponents": {
			Description: "Query a list of Component.",
			Type: graphql.NewNonNull(&graphql.List{
				OfType: graphql.NewNonNull(object.Component),
			}),
			Args: graphql.FieldConfigArgument{
				"input": {
					Type: graphql.NewNonNull(object.QueryComponentsInput),
				},
			},
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				input := db.QueryComponentInput{}
				Cast(p.Args["input"], &input)
				return query.QueryComponents(apidb.Mem, input)
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
