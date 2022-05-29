package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"

	"gopkg.in/yaml.v3"
)

func main() {
	fPtr := flag.String("file", "", "YAML file path to import")
	urlPtr := flag.String("url", "", "URL to reach to import components")

	flag.Parse()

	if fPtr == nil {
		log.Fatalf("Pointer to file is not specified.")
	}
	if urlPtr == nil {
		log.Fatalf("Pointer to URL is not specified")
	}

	// Decode YAML
	f, err := os.Open(*fPtr)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	var r root
	if err := yaml.NewDecoder(f).Decode(&r); err != nil {
		log.Fatal(err)
	}

	// Add Components
	client := &http.Client{}
	for _, comp := range r.Components {
		createComp(client, *urlPtr, comp)
	}
}

type HTTPClient interface {
	Do(*http.Request) (*http.Response, error)
}

var _ HTTPClient = (*http.Client)(nil)

func createComp(client HTTPClient, url string, comp component) error {
	var gql = struct {
		Query     string         `json:"query"`
		Variables map[string]any `json:"variables"`
	}{
		Query: `
		  mutation AddComponent($input: AddComponentInput!) {
			addComponent(input: $input) {
			  id
			}
		  }
		`,
		Variables: map[string]any{
			"input": struct {
				Name   string   `json:"name"`
				CPEs23 []string `json:"cpes23"`
			}{
				Name:   comp.Name,
				CPEs23: comp.CPEs23,
			},
		},
	}
	gqlb, err := json.Marshal(gql)
	if err != nil {
		return err
	}
	req, _ := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(gqlb))
	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	var gqlRes = struct {
		Data *struct {
			AddComponent struct {
				ID string `json:"id"`
			} `json:"addComponent"`
		} `json:"data,omitempty"`
		Errors []any `json:"errors,omitempty"`
	}{}
	if err := json.NewDecoder(res.Body).Decode(&gqlRes); err != nil {
		return err
	}
	if gqlRes.Errors != nil {
		return fmt.Errorf("%v", gqlRes.Errors...)
	}
	fmt.Printf("Imported %s with id %s\n", comp.Name, gqlRes.Data.AddComponent.ID)
	return nil
}

type root struct {
	Components []component `yaml:"components"`
}

type component struct {
	Name   string   `yaml:"name"`
	CPEs23 []string `yaml:"cpes23"`
}
