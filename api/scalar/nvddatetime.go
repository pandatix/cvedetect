package scalar

import (
	"time"

	"github.com/graphql-go/graphql"
	"github.com/graphql-go/graphql/language/ast"
)

var NVDDateTime = graphql.NewScalar(graphql.ScalarConfig{
	Name:        "NVDDateTime",
	Description: "Timestamp as defined by the NVD, near the format defined by RFC 3339. Notice it does not include UTC, so it may need to be re-contextualized.",
	Serialize: func(value interface{}) interface{} {
		switch value := value.(type) {
		case time.Time:
			return value.Format("2006-01-02T15:04Z")
		case *time.Time:
			if value == nil {
				return nil
			}
			return value.Format("2006-01-02T15:04Z")
		default:
			return nil
		}
	},
	ParseValue: func(value interface{}) interface{} {
		switch value := value.(type) {
		case string:
			return parseValueNVDDateTime(value)
		case *string:
			if value == nil {
				return nil
			}
			return parseValueNVDDateTime(*value)
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

func parseValueNVDDateTime(ts string) interface{} {
	t, err := time.Parse("2006-01-02T15:04Z", ts)
	if err != nil {
		return nil
	}
	return t
}
