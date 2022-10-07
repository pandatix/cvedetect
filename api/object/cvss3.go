package object

import (
	"strings"

	"github.com/graphql-go/graphql"
	"github.com/pandatix/cvedetect/api/scalar"
	gocvss30 "github.com/pandatix/go-cvss/30"
	gocvss31 "github.com/pandatix/go-cvss/31"
)

var CVSS3 = graphql.NewObject(graphql.ObjectConfig{
	Name:        "CVSS3",
	Description: "Representation of a CVSS v3 vector.",
	Fields: graphql.Fields{
		"vector": {
			Type: graphql.NewNonNull(scalar.CVSS3Vector),
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
					return (*vector)[5:8], nil
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
					if strings.HasPrefix(*vector, "CVSS:3.0") {
						cvss30, _ := gocvss30.ParseVector(*vector)
						return cvss30.BaseScore(), nil
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
					if strings.HasPrefix(*vector, "CVSS:3.0") {
						cvss30, _ := gocvss30.ParseVector(*vector)
						return cvss30.TemporalScore(), nil
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
					if strings.HasPrefix(*vector, "CVSS:3.0") {
						cvss30, _ := gocvss30.ParseVector(*vector)
						return cvss30.EnvironmentalScore(), nil
					}
					cvss31, _ := gocvss31.ParseVector(*vector)
					return cvss31.EnvironmentalScore(), nil
				}
				return nil, nil
			},
		},
	},
})
