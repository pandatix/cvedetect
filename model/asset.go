package model

type Asset struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	CPE23        string   `json:"cpe23"`
	Dependents   []*Asset `json:"dependents"`
	Dependencies []*Asset `json:"dependencies"`
	CVEs         []*CVE   `json:"cves"`
}
