package scalar

import (
	"github.com/graphql-go/graphql"
	"github.com/graphql-go/graphql/language/ast"
	"github.com/knqyf263/go-cpe/naming"
)

var CPE23 = graphql.NewScalar(graphql.ScalarConfig{
	Name:        "CPE23",
	Description: "CPE v2.3 string as defined by NIST-IR 7695.",
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
			return parseValueCPE23(value)
		case *string:
			if value == nil {
				return nil
			}
			return parseValueCPE23(*value)
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

func parseValueCPE23(cpe23 string) interface{} {
	// TODO use github.com/pandatix/go-cpe/naming ASAP
	if _, err := naming.UnbindFS(cpe23); err != nil {
		return nil
	}
	return cpe23
}
