package scalar

import (
	"github.com/graphql-go/graphql"
	"github.com/graphql-go/graphql/language/ast"
	gocvss30 "github.com/pandatix/go-cvss/30"
)

var CVSS30Vector = graphql.NewScalar(graphql.ScalarConfig{
	Name:        "CVSS30Vector",
	Description: "CVSS v3.0 vector as defined by first.org.",
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
			return parseValueCVSS30(value)
		case *string:
			if value == nil {
				return nil
			}
			return parseValueCVSS30(*value)
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

func parseValueCVSS30(cvss30vector string) interface{} {
	if _, err := gocvss30.ParseVector(cvss30vector); err != nil {
		return nil
	}
	return cvss30vector
}
