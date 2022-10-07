package db

import "time"

// Asset

type GetAssetInput struct {
	ID string `json:"id"`
}

type QueryAssetInput struct {
	VP *string `json:"vp,omitempty"`
}

type AddAssetInput struct {
	ID       string                `json:"id"`
	Name     string                `json:"name"`
	CPE23    string                `json:"cpe23"`
	Parents  []AddAssetParentInput `json:"parents"`
	Children []AddAssetChildInput  `json:"children"`
}

type AddAssetParentInput struct {
	ID string `json:"id"`
}

type AddAssetChildInput struct {
	ID string `json:"id"`
}

type UpdateAssetInput struct {
	ID       string                   `json:"id"`
	Name     *string                  `json:"name,omitempty"`
	CPE23    *string                  `json:"cpe23,omitempty"`
	Parents  []UpdateAssetParentInput `json:"parents,omitempty"`
	Children []UpdateAssetChildInput  `json:"children,omitempty"`
	CVEs     []UpdateAssetCVEsInput   `json:"cves,omitempty"`
}

type UpdateAssetParentInput struct {
	ID string `json:"id"`
}

type UpdateAssetChildInput struct {
	ID string `json:"id"`
}

type UpdateAssetCVEsInput struct {
	ID string `json:"id"`
}

type DeleteAssetInput struct {
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
	CVSS2Vector     *string                `json:"cvss2Vector,omitempty"`
	CVSS3Vector     *string                `json:"cvss3Vector,omitempty"`
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
	Name      string   `json:"name"`
	Refsource string   `json:"refsource"`
	Tags      []string `json:"tags"`
}

type UpdateCVEInput struct {
	ID             string                     `json:"id"`
	Description    *string                    `json:"description,omitempty"`
	LastUpdate     *time.Time                 `json:"lastUpdate"`
	CVSS2Vector    *string                    `json:"cvss2Vector,omitempty"`
	CVSS3Vector    *string                    `json:"cvss3Vector,omitempty"`
	Configurations []UpdateCVENodeInput       `json:"configurations"`
	Assets         []UpdateCVEAssetInput      `json:"assets"`
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

type UpdateCVEAssetInput struct {
	ID string `json:"id"`
}

type UpdateCVEReferencesInput struct {
	URL       string   `json:"url"`
	Name      string   `json:"name"`
	Refsource string   `json:"refsource"`
	Tags      []string `json:"tags"`
}

type DeleteCVEInput struct {
	ID string `json:"id"`
}
