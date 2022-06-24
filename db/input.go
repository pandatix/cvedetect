package db

import "time"

// Component

type GetComponentInput struct {
	ID string `json:"id"`
}

type QueryComponentInput struct {
	VP *string `json:"vp,omitempty"`
}

type AddComponentInput struct {
	ID       string                   `json:"id"`
	Name     string                   `json:"name"`
	CPEs23   []string                 `json:"cpes23"`
	Parent   *AddComponentParent      `json:"parent,omitempty"`
	Children []AddComponentChildInput `json:"children"`
}

type AddComponentParent struct {
	ID string `json:"id"`
}

type AddComponentChildInput struct {
	ID string `json:"id"`
}

type UpdateComponentInput struct {
	ID       string                      `json:"id"`
	Name     *string                     `json:"name,omitempty"`
	CPEs23   []string                    `json:"cpes23,omitempty"`
	Parent   *UpdateComponentParentInput `json:"parent,omitempty"`
	Children []UpdateComponentChildInput `json:"children,omitempty"`
	CVEs     []UpdateComponentCVEsInput  `json:"cves,omitempty"`
}

type UpdateComponentParentInput struct {
	ID string `json:"id"`
}

type UpdateComponentChildInput struct {
	ID string `json:"id"`
}

type UpdateComponentCVEsInput struct {
	ID string `json:"id"`
}

type DeleteComponentInput struct {
	ID string `json:"id"`
}

// CVE

type GetCVEInput struct {
	ID string `json:"id"`
}

type QueryCVEInput struct {
	VP *string `json:"vp,omitempty"`
}

type AddCVEInput struct {
	ID              string                 `json:"id"`
	Description     string                 `json:"description"`
	PublicationDate time.Time              `json:"publicationDate"`
	LastUpdate      time.Time              `json:"lastUpdate"`
	CVSS20Vector    *string                `json:"cvss20Vector,omitempty"`
	CVSS30Vector    *string                `json:"cvss30Vector,omitempty"`
	CVSS31Vector    *string                `json:"cvss31Vector,omitempty"`
	Configurations  []AddCVENodeInput      `json:"configurations"`
	References      []AddCVEReferenceInput `json:"references"`
}

type AddCVENodeInput struct {
	Negate     *bool                     `json:"negate,omitempty"`
	Operator   string                    `json:"operator"`
	Children   []AddCVENodeInput         `json:"children"`
	CPEMatches []AddCVENodeCPEMatchInput `json:"cpeMatches"`
}

type AddCVENodeCPEMatchInput struct {
	Vulnerable            bool    `json:"vulnerable"`
	CPE23                 string  `json:"cpe23"`
	VersionStartIncluding *string `json:"versionStartIncluding,omitempty"`
	VersionStartExcluding *string `json:"versionStartExcluding,omitempty"`
	VersionEndIncluding   *string `json:"versionEndIncluding,omitempty"`
	VersionEndExcluding   *string `json:"versionEndExcluding,omitempty"`
}

type AddCVEReferenceInput struct {
	URL       string   `json:"url"`
	Refsource string   `json:"refsource"`
	Tags      []string `json:"tags"`
}

type UpdateCVEInput struct {
	ID             string                     `json:"id"`
	Description    *string                    `json:"description,omitempty"`
	LastUpdate     *time.Time                 `json:"lastUpdate"`
	CVSS20Vector   *string                    `json:"cvss20Vector,omitempty"`
	CVSS30Vector   *string                    `json:"cvss30Vector,omitempty"`
	CVSS31Vector   *string                    `json:"cvss31Vector,omitempty"`
	Configurations []UpdateCVENodeInput       `json:"configurations"`
	Components     []UpdateCVEComponentInput  `json:"components"`
	References     []UpdateCVEReferencesInput `json:"references"`
}

type UpdateCVENodeInput struct {
	Negate     *bool                        `json:"negate,omitempty"`
	Operator   string                       `json:"operator"`
	Children   []UpdateCVENodeInput         `json:"children"`
	CPEMatches []UpdateCVENodeCPEMatchInput `json:"cpeMatches"`
}

type UpdateCVENodeCPEMatchInput struct {
	Vulnerable            bool    `json:"vulnerable"`
	CPE23                 string  `json:"cpe23"`
	VersionStartIncluding *string `json:"versionStartIncluding,omitempty"`
	VersionStartExcluding *string `json:"versionStartExcluding,omitempty"`
	VersionEndIncluding   *string `json:"versionEndIncluding,omitempty"`
	VersionEndExcluding   *string `json:"versionEndExcluding,omitempty"`
}

type UpdateCVEComponentInput struct {
	ID string `json:"id"`
}

type UpdateCVEReferencesInput struct {
	URL       string   `json:"url"`
	Refsource string   `json:"refsource"`
	Tags      []string `json:"tags"`
}

type DeleteCVEInput struct {
	ID string `json:"id"`
}
