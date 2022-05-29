package api

import "github.com/graphql-go/graphql"

var Schema = must(graphql.NewSchema(graphql.SchemaConfig{
	Query:    QueryObject,
	Mutation: MutationObject,
}))

func must[T any](t T, err error) T {
	if err != nil {
		panic(err)
	}
	return t
}
