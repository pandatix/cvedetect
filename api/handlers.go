package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/graphql-go/graphql"
)

func HandleGraphQLReq(w http.ResponseWriter, req *http.Request) {
	switch req.Method {
	case http.MethodGet:
		v := map[string]any{}
		if err := json.Unmarshal([]byte(req.URL.Query().Get("variables")), &v); err != nil {
			http.Error(w, fmt.Sprintf("invalid format for variables: %s", err), http.StatusBadRequest)
		}
		handleGQL(w, req, req.URL.Query().Get("query"), v)

	case http.MethodPost:
		b, err := io.ReadAll(req.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		type gqlreq struct {
			Query     string         `json:"query"`
			Variables map[string]any `json:"variables"`
		}
		var gql gqlreq
		if err := json.Unmarshal(b, &gql); err != nil {
			http.Error(w, fmt.Sprintf("invalid GraphQL query: %s", err), http.StatusBadRequest)
		}
		handleGQL(w, req, gql.Query, gql.Variables)

	default:
		http.Error(w, "invalid method", http.StatusBadRequest)
	}
}

func handleGQL(w http.ResponseWriter, req *http.Request, rs string, v map[string]any) {
	res := graphql.Do(graphql.Params{
		Schema:         Schema,
		RequestString:  rs,
		VariableValues: v,
	})
	if err := json.NewEncoder(w).Encode(res); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
	}
}
