package model

import "time"

type CVE struct {
	ID              string       `json:"id"`
	Description     string       `json:"description"`
	PublicationDate time.Time    `json:"publicationDate"`
	LastUpdate      time.Time    `json:"lastUpdate"`
	CVSS20Vector    *string      `json:"cvss20Vector,omitempty"`
	CVSS30Vector    *string      `json:"cvss30Vector,omitempty"`
	CVSS31Vector    *string      `json:"cvss31Vector,omitempty"`
	Configurations  []*Node      `json:"configurations"`
	Components      []*Component `json:"components"`
	References      []*Reference `json:"references"`
}

type Node struct {
	Negate     *bool       `json:"negate,omitempty"`
	Operator   string      `json:"operator"`
	Children   []*Node     `json:"children"`
	CPEMatches []*CPEMatch `json:"cpeMatches"`
}

type CPEMatch struct {
	Vulnerable            bool    `json:"vulnerable"`
	CPE23                 string  `json:"cpe23"`
	VersionStartIncluding *string `json:"versionStartIncluding"`
	VersionStartExcluding *string `json:"versionStartExcluding"`
	VersionEndIncluding   *string `json:"versionEndIncluding"`
	VersionEndExcluding   *string `json:"versionEndExcluding"`
}

type Reference struct {
	URL       string   `json:"url"`
	Name      string   `json:"name"`
	Refsource string   `json:"refsource"`
	Tags      []string `json:"tags"`
}
