package scalar

import (
	"strings"

	"github.com/graphql-go/graphql"
	"github.com/graphql-go/graphql/language/ast"
	gocvss30 "github.com/pandatix/go-cvss/30"
	gocvss31 "github.com/pandatix/go-cvss/31"
)

var CVSS3Vector = graphql.NewScalar(graphql.ScalarConfig{
	Name:        "CVSS3Vector",
	Description: "CVSS v3 vector as defined by first.org. Supports CVSS v3.0 and v3.1.",
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
			return parseValueCVSS3(value)
		case *string:
			if value == nil {
				return nil
			}
			return parseValueCVSS3(*value)
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

func parseValueCVSS3(vector string) interface{} {
	if strings.HasPrefix(vector, "CVSS:3.0") {
		if _, err := gocvss30.ParseVector(vector); err != nil {
			return nil
		}
		return vector
	}
	if _, err := gocvss31.ParseVector(vector); err != nil {
		return nil
	}
	return vector
}
