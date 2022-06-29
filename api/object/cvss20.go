package object

import (
	"github.com/graphql-go/graphql"
	"github.com/pandatix/cvedetect/api/scalar"
	gocvss20 "github.com/pandatix/go-cvss/20"
)

var CVSS20 = graphql.NewObject(graphql.ObjectConfig{
	Name:        "CVSS20",
	Description: "Representation of a CVSS v2.0 vector.",
	Fields: graphql.Fields{
		"vector": {
			Type: graphql.NewNonNull(scalar.CVSS30Vector),
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
					cvss31, _ := gocvss20.ParseVector(*vector)
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
					cvss31, _ := gocvss20.ParseVector(*vector)
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
					cvss31, _ := gocvss20.ParseVector(*vector)
					return cvss31.EnvironmentalScore(), nil
				}
				return nil, nil
			},
		},
	},
})
