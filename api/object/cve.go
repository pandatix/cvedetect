package object

import (
	"github.com/graphql-go/graphql"
	apidb "github.com/pandatix/cvedetect/api/db"
	"github.com/pandatix/cvedetect/api/scalar"
	"github.com/pandatix/cvedetect/model"
)

var CVE = graphql.NewObject(graphql.ObjectConfig{
	Name:        "CVE",
	Description: "CVE object according to the NVD.",
	Fields: graphql.Fields{
		"id": {
			Type: graphql.NewNonNull(scalar.CVEID),
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				if cve, ok := p.Source.(*model.CVE); ok {
					return cve.ID, nil
				}
				return nil, nil
			},
		},
		"description": {
			Type: graphql.NewNonNull(graphql.String),
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				if cve, ok := p.Source.(*model.CVE); ok {
					return cve.Description, nil
				}
				return nil, nil
			},
		},
		"publicationDate": {
			Type: graphql.NewNonNull(scalar.NVDDateTime),
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				if cve, ok := p.Source.(*model.CVE); ok {
					return cve.PublicationDate, nil
				}
				return nil, nil
			},
		},
		"lastUpdate": {
			Type: graphql.NewNonNull(scalar.NVDDateTime),
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				if cve, ok := p.Source.(*model.CVE); ok {
					return cve.LastUpdate, nil
				}
				return nil, nil
			},
		},
		"cvss20vector": {
			Type: graphql.String,
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				if cve, ok := p.Source.(*model.CVE); ok {
					return cve.CVSS20Vector, nil
				}
				return nil, nil
			},
		},
		"cvss31": {
			Type: CVSS31,
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				if cve, ok := p.Source.(*model.CVE); ok {
					return cve.CVSS31Vector, nil
				}
				return nil, nil
			},
		},
		"configurations": {
			Type: graphql.NewNonNull(&graphql.List{
				OfType: graphql.NewNonNull(Node),
			}),
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				if cve, ok := p.Source.(*model.CVE); ok {
					return cve.Configurations, nil
				}
				return nil, nil
			},
		},
		"references": {
			Type: graphql.NewNonNull(&graphql.List{
				OfType: graphql.NewNonNull(Reference),
			}),
			Args: graphql.FieldConfigArgument{
				"tags": {
					Type: &graphql.List{
						OfType: graphql.NewNonNull(graphql.String),
					},
				},
			},
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				if cve, ok := p.Source.(*model.CVE); ok {
					t := p.Args["tags"].([]any)
					if len(t) == 0 {
						return cve.References, nil
					}
					tags := make([]string, len(t))
					for i, tref := range t {
						tags[i] = tref.(string)
					}
					references := []*model.Reference{}
					for _, ref := range cve.References {
						if containsAny(ref.Tags, tags) {
							references = append(references, ref)
						}
					}
					return references, nil
				}
				return nil, nil
			},
		},
	},
})

func contains(slc []string, target string) bool {
	for _, str := range slc {
		if str == target {
			return true
		}
	}
	return false
}

func containsAny(slc, targets []string) bool {
	for _, target := range targets {
		if contains(slc, target) {
			return true
		}
	}
	return false
}

var Node = graphql.NewObject(graphql.ObjectConfig{
	Name:        "Node",
	Description: "Node is a configuration node as defined by the NVD.",
	Fields: graphql.Fields{
		"negate": {
			Type: graphql.Boolean,
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				if node, ok := p.Source.(*model.Node); ok {
					return node.Negate, nil
				}
				return nil, nil
			},
		},
		"operator": {
			Type: graphql.NewNonNull(graphql.String),
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				if node, ok := p.Source.(*model.Node); ok {
					return node.Operator, nil
				}
				return nil, nil
			},
		},
		"cpeMatches": {
			Type: graphql.NewNonNull(&graphql.List{
				OfType: graphql.NewNonNull(CPEMatch),
			}),
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				if node, ok := p.Source.(*model.Node); ok {
					return node.CPEMatches, nil
				}
				return nil, nil
			},
		},
	},
})

var CPEMatch = graphql.NewObject(graphql.ObjectConfig{
	Name:        "CPEMatch",
	Description: "CPEMatch is a CPE match configuration as defined by the NVD.",
	Fields: graphql.Fields{
		"vulnerable": {
			Type: graphql.NewNonNull(graphql.Boolean),
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				if cpeMatch, ok := p.Source.(*model.CPEMatch); ok {
					return cpeMatch.Vulnerable, nil
				}
				return nil, nil
			},
		},
		"cpe23": {
			Type: graphql.NewNonNull(scalar.CPE23),
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				if cpeMatch, ok := p.Source.(*model.CPEMatch); ok {
					return cpeMatch.CPE23, nil
				}
				return nil, nil
			},
		},
		"versionStartIncluding": {
			// TODO use a scalar for NIST-IR 7695 Figure 5-1
			Type: graphql.String,
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				if cpeMatch, ok := p.Source.(*model.CPEMatch); ok {
					return cpeMatch.VersionStartIncluding, nil
				}
				return nil, nil
			},
		},
		"versionStartExcluding": {
			// TODO use a scalar for NIST-IR 7695 Figure 5-1
			Type: graphql.String,
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				if cpeMatch, ok := p.Source.(*model.CPEMatch); ok {
					return cpeMatch.VersionStartExcluding, nil
				}
				return nil, nil
			},
		},
		"versionEndIncluding": {
			// TODO use a scalar for NIST-IR 7695 Figure 5-1
			Type: graphql.String,
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				if cpeMatch, ok := p.Source.(*model.CPEMatch); ok {
					return cpeMatch.VersionEndIncluding, nil
				}
				return nil, nil
			},
		},
		"versionEndExcluding": {
			// TODO use a scalar for NIST-IR 7695 Figure 5-1
			Type: graphql.String,
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				if cpeMatch, ok := p.Source.(*model.CPEMatch); ok {
					return cpeMatch.VersionEndExcluding, nil
				}
				return nil, nil
			},
		},
	},
})

var Reference = graphql.NewObject(graphql.ObjectConfig{
	Name: "Reference",
	Fields: graphql.Fields{
		"url": {
			Type: graphql.NewNonNull(graphql.String),
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				if ref, ok := p.Source.(*model.Reference); ok {
					return ref.URL, nil
				}
				return nil, nil
			},
		},
		"refsource": {
			Type: graphql.NewNonNull(graphql.String),
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				if ref, ok := p.Source.(*model.Reference); ok {
					return ref.Refsource, nil
				}
				return nil, nil
			},
		},
		"tags": {
			Type: graphql.NewNonNull(&graphql.List{
				OfType: graphql.NewNonNull(graphql.String),
			}),
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				if ref, ok := p.Source.(*model.Reference); ok {
					return ref.Tags, nil
				}
				return nil, nil
			},
		},
	},
})

var GetCVEInput = graphql.NewInputObject(graphql.InputObjectConfig{
	Name: "GetCVEInput",
	Fields: graphql.InputObjectConfigFieldMap{
		"id": {
			Type: graphql.NewNonNull(scalar.CVEID),
		},
	},
})

// TODO add filtering on score
var QueryCVEsInput = graphql.NewInputObject(graphql.InputObjectConfig{
	Name: "QueryCVEsInput",
	Fields: graphql.InputObjectConfigFieldMap{
		"vp": {
			Type:        graphql.String,
			Description: "\"vendor:product\" couple to look for.",
		},
	},
})

var AddCVEInput = graphql.NewInputObject(graphql.InputObjectConfig{
	Name: "AddCVEInput",
	Fields: graphql.InputObjectConfigFieldMap{
		"id": {
			Type: graphql.NewNonNull(scalar.CVEID),
		},
		"description": {
			Type: graphql.NewNonNull(graphql.String),
		},
		"publicationDate": {
			Type: graphql.NewNonNull(scalar.NVDDateTime),
		},
		"lastUpdate": {
			Type: graphql.NewNonNull(scalar.NVDDateTime),
		},
		"cvss20vector": {
			// TODO use CVSS20Vector scalar
			Type: graphql.String,
		},
		"cvss31vector": {
			// TODO use CVSS31Vector scalar
			Type: graphql.String,
		},
		"configurations": {
			Type: AddCVENodeInput,
		},
		"references": {
			Type: AddCVEReferencesInput,
		},
	},
})

var AddCVENodeInput = graphql.NewInputObject(graphql.InputObjectConfig{
	Name: "AddCVENodeInput",
	Fields: graphql.InputObjectConfigFieldMap{
		"negate": {
			Type: graphql.Boolean,
		},
		"operator": {
			Type: graphql.NewNonNull(graphql.String),
		},
		"cpeMatches": {
			Type: &graphql.List{
				OfType: graphql.NewNonNull(AddCVENodeCPEMatchInput),
			},
		},
	},
})

var AddCVENodeCPEMatchInput = graphql.NewInputObject(graphql.InputObjectConfig{
	Name: "AddCVENodeCPEMatchInput",
	Fields: graphql.InputObjectConfigFieldMap{
		"vulnerable": {
			Type: graphql.NewNonNull(graphql.Boolean),
		},
		"cpe23": {
			Type: graphql.NewNonNull(scalar.CPE23),
		},
		"versionStartIncluding": {
			Type: graphql.Boolean,
		},
		"versionStartExcluding": {
			Type: graphql.Boolean,
		},
		"versionEndIncluding": {
			Type: graphql.Boolean,
		},
		"versionEndExcluding": {
			Type: graphql.Boolean,
		},
	},
})

var AddCVEReferencesInput = graphql.NewInputObject(graphql.InputObjectConfig{
	Name: "AddCVEReferencesInput",
	Fields: graphql.InputObjectConfigFieldMap{
		"url": {
			Type: graphql.NewNonNull(graphql.String),
		},
		"refsource": {
			Type: graphql.NewNonNull(graphql.String),
		},
		"tags": {
			Type: graphql.NewNonNull(&graphql.List{
				OfType: graphql.NewNonNull(graphql.String),
			}),
		},
	},
})

var UpdateCVEInput = graphql.NewInputObject(graphql.InputObjectConfig{
	Name: "UpdateCVEInput",
	Fields: graphql.InputObjectConfigFieldMap{
		"id": {
			Type: graphql.NewNonNull(scalar.CVEID),
		},
		"description": {
			Type: graphql.String,
		},
		"lastUpdate": {
			Type: scalar.NVDDateTime,
		},
		"cvss20vector": {
			// TODO use CVSS20Vector scalar
			Type: graphql.String,
		},
		"cvss31vector": {
			// TODO use CVSS31Vector scalar
			Type: graphql.String,
		},
		"configurations": {
			Type: UpdateCVENodeInput,
		},
		"references": {
			Type: UpdateCVEReferencesInput,
		},
	},
})

var UpdateCVENodeInput = graphql.NewInputObject(graphql.InputObjectConfig{
	Name: "UpdateCVENodeInput",
	Fields: graphql.InputObjectConfigFieldMap{
		"negate": {
			Type: graphql.Boolean,
		},
		"operator": {
			Type: graphql.NewNonNull(graphql.String),
		},
		"cpeMatches": {
			Type: &graphql.List{
				OfType: graphql.NewNonNull(UpdateCVENodeCPEMatchInput),
			},
		},
	},
})

var UpdateCVENodeCPEMatchInput = graphql.NewInputObject(graphql.InputObjectConfig{
	Name: "UpdateCVENodeCPEMatchInput",
	Fields: graphql.InputObjectConfigFieldMap{
		"vulnerable": {
			Type: graphql.NewNonNull(graphql.Boolean),
		},
		"cpe23": {
			Type: graphql.NewNonNull(scalar.CPE23),
		},
		"versionStartIncluding": {
			Type: graphql.Boolean,
		},
		"versionStartExcluding": {
			Type: graphql.Boolean,
		},
		"versionEndIncluding": {
			Type: graphql.Boolean,
		},
		"versionEndExcluding": {
			Type: graphql.Boolean,
		},
	},
})

var UpdateCVEReferencesInput = graphql.NewInputObject(graphql.InputObjectConfig{
	Name: "UpdateCVEReferencesInput",
	Fields: graphql.InputObjectConfigFieldMap{
		"url": {
			Type: graphql.NewNonNull(graphql.String),
		},
		"refsource": {
			Type: graphql.NewNonNull(graphql.String),
		},
		"tags": {
			Type: graphql.NewNonNull(&graphql.List{
				OfType: graphql.NewNonNull(graphql.String),
			}),
		},
	},
})

var DeleteCVEInput = graphql.NewInputObject(graphql.InputObjectConfig{
	Name: "DeleteCVEInput",
	Fields: graphql.InputObjectConfigFieldMap{
		"id": {
			Type: graphql.NewNonNull(scalar.CVEID),
		},
	},
})

func init() {
	CVE.AddFieldConfig("components", &graphql.Field{
		Type: graphql.NewNonNull(&graphql.List{
			OfType: graphql.NewNonNull(Component),
		}),
		Resolve: func(p graphql.ResolveParams) (interface{}, error) {
			if cve, ok := p.Source.(*model.CVE); ok {
				return apidb.Mem.GetCVEComponents(cve), nil
			}
			return nil, nil
		},
	})
	Node.AddFieldConfig("children", &graphql.Field{
		Type: graphql.NewNonNull(&graphql.List{
			OfType: graphql.NewNonNull(Node),
		}),
	})
	AddCVENodeInput.AddFieldConfig("children", &graphql.InputObjectFieldConfig{
		Type: &graphql.List{
			OfType: graphql.NewNonNull(AddCVENodeInput),
		},
	})
	UpdateCVENodeInput.AddFieldConfig("children", &graphql.InputObjectFieldConfig{
		Type: &graphql.List{
			OfType: graphql.NewNonNull(UpdateCVENodeInput),
		},
	})
}
