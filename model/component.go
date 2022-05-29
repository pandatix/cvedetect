package model

type Component struct {
	ID       string       `json:"id"`
	Name     string       `json:"name"`
	CPEs23   []string     `json:"cpes23"`
	Parent   *Component   `json:"parent"`
	Children []*Component `json:"children"`
	CVEs     []*CVE       `json:"cves"`
}
