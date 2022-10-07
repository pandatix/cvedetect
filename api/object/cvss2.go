package object

import (
	"github.com/graphql-go/graphql"
	"github.com/pandatix/cvedetect/api/scalar"
	gocvss20 "github.com/pandatix/go-cvss/20"
)

var CVSS2 = graphql.NewObject(graphql.ObjectConfig{
	Name:        "CVSS2",
	Description: "Representation of a CVSS v2.0 vector.",
	Fields: graphql.Fields{
		"vector": {
			Type: graphql.NewNonNull(scalar.CVSS2Vector),
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
		"version": {
			Type: graphql.NewNonNull(graphql.String),
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				if vector, ok := p.Source.(*string); ok {
					if vector == nil {
						return nil, nil
					}
					return "2.0", nil
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
					cvss20, _ := gocvss20.ParseVector(*vector)
					return cvss20.BaseScore(), nil
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
					cvss20, _ := gocvss20.ParseVector(*vector)
					return cvss20.TemporalScore(), nil
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
					cvss20, _ := gocvss20.ParseVector(*vector)
					return cvss20.EnvironmentalScore(), nil
				}
				return nil, nil
			},
		},
	},
})
