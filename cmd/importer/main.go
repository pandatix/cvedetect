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
	urlPtr := flag.String("url", "", "URL to reach to import assets")

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

	// Add Assets
	client := &http.Client{}
	for _, asset := range r.Assets {
		if err := createAsset(client, *urlPtr, asset); err != nil {
			log.Fatal(err)
		}
	}
}

type HTTPClient interface {
	Do(*http.Request) (*http.Response, error)
}

var _ HTTPClient = (*http.Client)(nil)

func createAsset(client HTTPClient, url string, asset asset) error {
	var gql = struct {
		Query     string         `json:"query"`
		Variables map[string]any `json:"variables"`
	}{
		Query: `
		  mutation AddAsset($input: AddAssetInput!) {
			addAsset(input: $input) {
			  id
			}
		  }
		`,
		Variables: map[string]any{
			"input": map[string]any{
				"name":  asset.Name,
				"cpe23": asset.CPE23,
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
			AddAsset struct {
				ID string `json:"id"`
			} `json:"addAsset"`
		} `json:"data,omitempty"`
		Errors []any `json:"errors,omitempty"`
	}{}
	if err := json.NewDecoder(res.Body).Decode(&gqlRes); err != nil {
		return err
	}
	if gqlRes.Errors != nil {
		return fmt.Errorf("%v", gqlRes.Errors...)
	}
	fmt.Printf("Imported %s with id %s\n", asset.Name, gqlRes.Data.AddAsset.ID)
	return nil
}

type root struct {
	Assets []asset `yaml:"assets"`
}

type asset struct {
	Name  string `yaml:"name"`
	CPE23 string `yaml:"cpe23"`
}
