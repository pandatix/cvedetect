package model

type Component struct {
	ID       string       `json:"id"`
	Name     string       `json:"name"`
	CPE23    string       `json:"cpe23"`
	Parent   *Component   `json:"parent"`
	Children []*Component `json:"children"`
	CVEs     []*CVE       `json:"cves"`
}
