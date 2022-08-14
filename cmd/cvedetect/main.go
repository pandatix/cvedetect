package main

import (
	"archive/zip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/pandatix/cvedetect/api"
	apidb "github.com/pandatix/cvedetect/api/db"
	"github.com/pandatix/cvedetect/db"
	"github.com/pandatix/nvdapi"
	"github.com/urfave/cli/v2"
)

const (
	startYear  = 2002
	url        = "https://nvd.nist.gov/feeds/json/cve/1.1/"
	fileFormat = "nvdcve-1.1-%d.json"
)

func main() {
	app := cli.App{
		Name:        "CVE-Detect",
		Version:     "v0.1.0-alpha",
		Description: "Implementation of personnal researches on CVE detection, exposing a GraphQL API to work with.",
		Flags: []cli.Flag{
			cli.HelpFlag,
			cli.VersionFlag,
			// NVD load process
			&cli.BoolFlag{
				Name:    "download",
				EnvVars: []string{"DOWNLOAD"},
				Value:   false,
			},
			&cli.StringFlag{
				Name:     "nvd-directory",
				Aliases:  []string{"d"},
				EnvVars:  []string{"NVD_DIRECTORY"},
				Required: true,
			},
			// Web server
			&cli.StringFlag{
				Name:    "port",
				Aliases: []string{"p"},
				EnvVars: []string{"PORT"},
				Value:   "8080",
			},
		},
		Authors: []*cli.Author{
			{
				Name:  "Lucas TESSON",
				Email: "lucastesson@protonmail.com",
			},
		},
		Action: run,
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}

func run(ctx *cli.Context) error {
	dir := ctx.String("nvd-directory")
	currYear := time.Now().Year()

	// Download NVD
	if ctx.Bool("download") {
		fmt.Printf("📩 Downloading NVD\n")

		// Create directory if not exist
		_, err := os.Open(dir)
		if os.IsNotExist(err) {
			fmt.Printf("   Directory %s does not exist. Creating it.\n", dir)
			if err := os.Mkdir(dir, 0766); err != nil {
				return err
			}
		} else if err != nil {
			return err
		}

		client := &http.Client{}
		for i := 0; i <= currYear-startYear; i++ {
			fmt.Printf("   Year: %d\n", startYear+i)

			// Download archive
			req, _ := http.NewRequest(http.MethodGet, fmt.Sprintf(url+fileFormat+".zip", startYear+i), nil)
			res, err := client.Do(req)
			if err != nil {
				return err
			}
			defer res.Body.Close()
			b, err := io.ReadAll(res.Body)
			if err != nil {
				return err
			}

			// Write in file
			fName := fmt.Sprintf(dir+"/"+fileFormat+".zip", startYear+i)
			f, err := os.Create(fName)
			if err != nil {
				return err
			}
			defer f.Close()
			if _, err := f.Write(b); err != nil {
				return err
			}
		}
	}

	// Load CVEs in memory
	fmt.Printf("💽 Loading NVD\n")
	memory := db.NewMemory()
	for i := 0; i <= currYear-startYear; i++ {
		fmt.Printf("   Year: %d\n", startYear+i)

		// Open zip
		zipName := fmt.Sprintf(fileFormat+".zip", startYear+i)
		zrd, err := zip.OpenReader(dir + "/" + zipName)
		if err != nil {
			return err
		}
		defer zrd.Close()

		// Select file
		if len(zrd.File) != 1 {
			return errors.New("too many zipped file in " + zipName)
		}
		if zrd.File[0].Name != fmt.Sprintf(fileFormat, startYear+i) {
			return errors.New("invalid json file name in " + zipName)
		}

		// Read content
		f, err := zrd.File[0].Open()
		if err != nil {
			return err
		}
		defer f.Close()
		b, err := io.ReadAll(f)
		if err != nil {
			return err
		}
		content := &nvdapi.CVEResult{}
		if err = json.Unmarshal(b, &content); err != nil {
			return err
		}

		// Import in DB
		for _, item := range content.CVEItems {
			// Extract CVSS 2.0 vector
			var cvss20vector *string = nil
			if item.Impact != nil &&
				item.Impact.BaseMetricV2 != nil &&
				item.Impact.BaseMetricV2.CVSSV2 != nil {
				cvss20vector = &item.Impact.BaseMetricV2.CVSSV2.VectorString
			}
			// Extract CVSS 3.X vector
			var cvss30vector *string = nil
			var cvss31vector *string = nil
			if item.Impact != nil &&
				item.Impact.BaseMetricV3 != nil &&
				item.Impact.BaseMetricV3.CVSSV3 != nil {
				if item.Impact.BaseMetricV3.CVSSV3.Version == "3.0" {
					cvss30vector = &item.Impact.BaseMetricV3.CVSSV3.VectorString
				} else if item.Impact.BaseMetricV3.CVSSV3.Version == "3.1" {
					cvss31vector = &item.Impact.BaseMetricV3.CVSSV3.VectorString
				}
			}
			// Extract configurations
			var inputConfs []db.AddCVENodeInput = nil
			if item.Configurations != nil {
				inputConfs = make([]db.AddCVENodeInput, len(item.Configurations.Nodes))
				for i, node := range item.Configurations.Nodes {
					inputConfs[i] = loadNode(node)
				}
			}
			// Extract references
			references := make([]db.AddCVEReferenceInput, len(item.CVE.References.ReferenceData))
			for i, ref := range item.CVE.References.ReferenceData {
				references[i] = db.AddCVEReferenceInput{
					URL:       ref.URL,
					Name:      *ref.Name,
					Refsource: *ref.Refsource,
					Tags:      ref.Tags,
				}
			}
			// Import CVE
			if err := memory.AddCVE(db.AddCVEInput{
				ID:              item.CVE.CVEDataMeta.ID,
				Description:     item.CVE.Description.DescriptionData[0].Value,
				PublicationDate: timeParse(*item.PublishedDate),
				LastUpdate:      timeParse(*item.LastModifiedDate),
				CVSS20Vector:    cvss20vector,
				CVSS30Vector:    cvss30vector,
				CVSS31Vector:    cvss31vector,
				Configurations:  inputConfs,
				References:      references,
			}); err != nil {
				return err
			}
		}
	}
	fmt.Printf("📝 %d CVEs loaded.\n", len(memory.CVEs))

	// Start server
	port := fmt.Sprintf(":%d", ctx.Int("port"))
	apidb.Mem = memory
	fmt.Printf("📡 Serving HTTP server on %s\n", port)
	http.HandleFunc("/graphql", api.HandleGraphQLReq)
	if err := http.ListenAndServe(port, nil); err != nil {
		return err
	}

	return nil
}

func timeParse(ts string) time.Time {
	t, err := time.Parse("2006-01-02T15:04Z", ts)
	if err != nil {
		panic(err)
	}
	return t
}

func loadNode(node nvdapi.Node) db.AddCVENodeInput {
	var children []db.AddCVENodeInput = nil
	if node.Children != nil {
		children = make([]db.AddCVENodeInput, len(node.Children))
		for i, child := range node.Children {
			children[i] = loadNode(child)
		}
	}
	var cpeMatches []db.AddCVENodeCPEMatchInput = nil
	if node.CPEMatch != nil {
		cpeMatches = make([]db.AddCVENodeCPEMatchInput, len(node.CPEMatch))
		for i, cpeMatch := range node.CPEMatch {
			cpeMatches[i] = db.AddCVENodeCPEMatchInput{
				Vulnerable:            cpeMatch.Vulnerable,
				CPE23:                 cpeMatch.CPE23URI,
				VersionStartIncluding: cpeMatch.VersionStartIncluding,
				VersionStartExcluding: cpeMatch.VersionStartExcluding,
				VersionEndIncluding:   cpeMatch.VersionEndIncluding,
				VersionEndExcluding:   cpeMatch.VersionEndExcluding,
			}
		}
	}
	return db.AddCVENodeInput{
		Negate:     node.Negate,
		Operator:   *node.Operator,
		Children:   children,
		CPEMatches: cpeMatches,
	}
}
