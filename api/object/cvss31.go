package object

import (
	"github.com/graphql-go/graphql"
	"github.com/pandatix/cvedetect/api/scalar"
	gocvss31 "github.com/pandatix/go-cvss/31"
)

var CVSS31 = graphql.NewObject(graphql.ObjectConfig{
	Name:        "CVSS31",
	Description: "Representation of a CVSS v3.1 vector.",
	Fields: graphql.Fields{
		"vector": {
			Type: graphql.NewNonNull(scalar.CVSS31Vector),
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				if vector, ok := p.Source.(*string); ok {
					if vector == nil {
						return nil, nil
					}
					return vector, nil
				}
				return nil, nil
			},
		},
		"baseScore": {
			Type: graphql.NewNonNull(graphql.Float),
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				if vector, ok := p.Source.(*string); ok {
					if vector == nil {
						return nil, nil
					}
					cvss31, _ := gocvss31.ParseVector(*vector)
					return cvss31.BaseScore(), nil
				}
				return nil, nil
			},
		},
		"temporalScore": {
			Type: graphql.NewNonNull(graphql.Float),
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				if vector, ok := p.Source.(*string); ok {
					if vector == nil {
						return nil, nil
					}
					cvss31, _ := gocvss31.ParseVector(*vector)
					return cvss31.TemporalScore(), nil
				}
				return nil, nil
			},
		},
		"environmentalScore": {
			Type: graphql.NewNonNull(graphql.Float),
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				if vector, ok := p.Source.(*string); ok {
					if vector == nil {
						return nil, nil
					}
					cvss31, _ := gocvss31.ParseVector(*vector)
					return cvss31.EnvironmentalScore(), nil
				}
				return nil, nil
			},
		},
	},
})
