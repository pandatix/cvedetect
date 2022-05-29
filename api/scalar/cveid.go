package scalar

import (
	"regexp"

	"github.com/graphql-go/graphql"
	"github.com/graphql-go/graphql/language/ast"
)

var (
	regCVE = regexp.MustCompile(`^CVE\-\d{4}\-\d{4,7}$`)
)

var CVEID = graphql.NewScalar(graphql.ScalarConfig{
	Name:        "CVEID",
	Description: "CVE identifier as defined by cve.org.",
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
			return parseValueCVEID(value)
		case *string:
			if value == nil {
				return nil
			}
			return parseValueCVEID(*value)
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

func parseValueCVEID(cveid string) interface{} {
	if !regCVE.MatchString(cveid) {
		return nil
	}
	return cveid
}
