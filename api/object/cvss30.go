package object

import (
	"github.com/graphql-go/graphql"
	"github.com/pandatix/cvedetect/api/scalar"
	gocvss30 "github.com/pandatix/go-cvss/30"
)

var CVSS30 = graphql.NewObject(graphql.ObjectConfig{
	Name:        "CVSS30",
	Description: "Representation of a CVSS v3.0 vector.",
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
					cvss30, _ := gocvss30.ParseVector(*vector)
					return cvss30.BaseScore(), nil
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
					cvss30, _ := gocvss30.ParseVector(*vector)
					return cvss30.TemporalScore(), nil
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
					cvss30, _ := gocvss30.ParseVector(*vector)
					return cvss30.EnvironmentalScore(), nil
				}
				return nil, nil
			},
		},
	},
})
