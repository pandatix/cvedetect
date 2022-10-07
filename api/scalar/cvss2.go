package scalar

import (
	"github.com/graphql-go/graphql"
	"github.com/graphql-go/graphql/language/ast"
	gocvss20 "github.com/pandatix/go-cvss/20"
)

var CVSS2Vector = graphql.NewScalar(graphql.ScalarConfig{
	Name:        "CVSS2Vector",
	Description: "CVSS v2.0 vector as defined by first.org.",
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
			return parseValueCVSS2(value)
		case *string:
			if value == nil {
				return nil
			}
			return parseValueCVSS2(*value)
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

func parseValueCVSS2(cvss20vector string) interface{} {
	if _, err := gocvss20.ParseVector(cvss20vector); err != nil {
		return nil
	}
	return cvss20vector
}
