package mutation

import (
	"github.com/pandatix/cvedetect/db"
	"github.com/pandatix/cvedetect/detection"
	"github.com/pandatix/cvedetect/internal"
	"github.com/pandatix/cvedetect/model"
)

func AddAsset(mem *db.Memory, input db.AddAssetInput) (*model.Asset, error) {
	// Add asset
	if err := mem.AddAsset(input); err != nil {
		return nil, err
	}

	// Perform CVE detection
	if err := assetDetect(mem, input.CPE23, input.ID); err != nil {
		return nil, err
	}

	// Update Asset after possible detections
	return mem.GetAsset(db.GetAssetInput{
		ID: input.ID,
	})
}

func UpdateAsset(mem *db.Memory, input db.UpdateAssetInput) (*model.Asset, error) {
	// Update asset
	if err := mem.UpdateAsset(input); err != nil {
		return nil, err
	}

	// Perform CVE detection
	if input.CPE23 != nil {
		if err := assetDetect(mem, *input.CPE23, input.ID); err != nil {
			return nil, err
		}
	}

	return mem.GetAsset(db.GetAssetInput{
		ID: input.ID,
	})
}

func DeleteAsset(mem *db.Memory, input db.DeleteAssetInput) (*model.Asset, error) {
	// Pre-fetch asset that will be deleted
	//nolint:gosimple // For now it matches, but it's semantically not related
	asset, err := mem.GetAsset(db.GetAssetInput{
		ID: input.ID,
	})
	if err != nil {
		return nil, err
	}
	// Delete asset
	if err := mem.DeleteAsset(db.DeleteAssetInput{
		ID: input.ID,
	}); err != nil {
		return nil, err
	}
	return asset, nil
}

func assetDetect(mem *db.Memory, cpe23 string, assetID string) error {
	// Get related CVEs
	vp := internal.GetVP(cpe23)
	cves := mem.QueryCVEs(db.QueryCVEInput{
		VP: &vp,
	})

	// Run MDC1
	asset, _ := mem.GetAsset(db.GetAssetInput{
		ID: assetID,
	})
	matchingCVEs := []db.UpdateAssetCVEsInput{}
	for _, cve := range cves {
		if detection.MDC1(asset, cve) {
			matchingCVEs = append(matchingCVEs, db.UpdateAssetCVEsInput{
				ID: cve.ID,
			})
		}
	}

	// Update Asset to add matching CVEs
	if err := mem.UpdateAsset(db.UpdateAssetInput{
		ID:   assetID,
		CVEs: matchingCVEs,
	}); err != nil {
		return err
	}
	return nil
}
