package mutation

import (
	"github.com/pandatix/cvedetect/db"
	"github.com/pandatix/cvedetect/detection"
	"github.com/pandatix/cvedetect/internal"
	"github.com/pandatix/cvedetect/model"
)

func AddCVE(mem *db.Memory, input db.AddCVEInput) (*model.CVE, error) {
	// Add CVE
	if err := mem.AddCVE(input); err != nil {
		return nil, err
	}

	// Perform CVE detection
	if err := cveDetect(mem, input.ID); err != nil {
		return nil, err
	}

	// Update CVE after possible detections
	return mem.GetCVE(db.GetCVEInput{
		ID: input.ID,
	})
}

func UpdateCVE(mem *db.Memory, input db.UpdateCVEInput) (*model.CVE, error) {
	// Update CVE
	if err := mem.UpdateCVE(input); err != nil {
		return nil, err
	}

	// Perform CVE detection
	if err := cveDetect(mem, input.ID); err != nil {
		return nil, err
	}

	return mem.GetCVE(db.GetCVEInput{
		ID: input.ID,
	})
}

func DeleteCVE(mem *db.Memory, input db.DeleteCVEInput) (*model.CVE, error) {
	// Pre-fetch CVE that will be deleted
	//nolint:gosimple // For now it matches, but it's semantically not related
	cve, err := mem.GetCVE(db.GetCVEInput{
		ID: input.ID,
	})
	if err != nil {
		return nil, err
	}
	// Delete CVE
	if err := mem.DeleteCVE(db.DeleteCVEInput{
		ID: input.ID,
	}); err != nil {
		return nil, err
	}
	return cve, nil
}

func getCVECPEs23(mem *db.Memory, cveID string) []string {
	cve, _ := mem.GetCVE(db.GetCVEInput{
		ID: cveID,
	})
	cpes23 := []string{}
	for _, conf := range cve.Configurations {
		cpes23 = append(cpes23, getNodeCPEs23(conf)...)
	}
	return cpes23
}

func getNodeCPEs23(node *model.Node) []string {
	cpes23 := []string{}
	for _, child := range node.Children {
		cpes23 = append(cpes23, getNodeCPEs23(child)...)
	}
	for _, cpeMatch := range node.CPEMatches {
		cpes23 = append(cpes23, cpeMatch.CPE23)
	}
	return cpes23
}

func cveDetect(mem *db.Memory, cveID string) error {
	// Get CVE's Vendor-Product couples
	cpes23 := getCVECPEs23(mem, cveID)
	vpMap := map[string]struct{}{}
	for _, cpe23 := range cpes23 {
		vpMap[internal.GetVP(cpe23)] = struct{}{}
	}

	// Get related assets
	assets := []*model.Asset{}
	for vp := range vpMap {
		assets = append(assets, mem.QueryAssets(db.QueryAssetInput{
			VP: &vp,
		})...)
	}

	// Run MDC1
	cve, _ := mem.GetCVE(db.GetCVEInput{
		ID: cveID,
	})
	matchingAssets := []db.UpdateCVEAssetInput{}
	for _, asset := range assets {
		if detection.MDC1(asset, cve) {
			matchingAssets = append(matchingAssets, db.UpdateCVEAssetInput{
				ID: asset.ID,
			})
		}
	}

	// Update CVE to add matching Assets
	if err := mem.UpdateCVE(db.UpdateCVEInput{
		ID:     cveID,
		Assets: matchingAssets,
	}); err != nil {
		return err
	}
	return nil
}
