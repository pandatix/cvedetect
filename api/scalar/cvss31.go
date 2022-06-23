package scalar

import (
	"github.com/graphql-go/graphql"
	"github.com/graphql-go/graphql/language/ast"
	gocvss31 "github.com/pandatix/go-cvss/31"
)

var CVSS31Vector = graphql.NewScalar(graphql.ScalarConfig{
	Name:        "CVSS31Vector",
	Description: "CVSS v3.1 vector as defined by first.org.",
	Serialize: func(value interface{}) interface{} {
		switch value := value.(type) {
		case string:
			return value
		case *string:
			if value == nil {
				return nil
			}
			return *value
		default:
			return nil
		}
	},
	ParseValue: func(value interface{}) interface{} {
		switch value := value.(type) {
		case string:
			return parseValueCVSS31(value)
		case *string:
			if value == nil {
				return nil
			}
			return parseValueCVSS31(*value)
		default:
			return nil
		}
	},
	ParseLiteral: func(valueAST ast.Value) interface{} {
		switch valueAST := valueAST.(type) {
		case *ast.StringValue:
			return valueAST.Value
		default:
			return nil
		}
	},
})

func parseValueCVSS31(cvss31vector string) interface{} {
	if _, err := gocvss31.ParseVector(cvss31vector); err != nil {
		return nil
	}
	return cvss31vector
}
