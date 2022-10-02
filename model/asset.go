package model

type Asset struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	CPE23    string   `json:"cpe23"`
	Parent   *Asset   `json:"parent"`
	Children []*Asset `json:"children"`
	CVEs     []*CVE   `json:"cves"`
}
