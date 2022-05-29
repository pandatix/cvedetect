package mutation

import (
	"github.com/knqyf263/go-cpe/naming"
	"github.com/pandatix/cvedetect/db"
	"github.com/pandatix/cvedetect/detection"
	"github.com/pandatix/cvedetect/model"
)

func AddComponent(mem *db.Memory, input db.AddComponentInput) (*model.Component, error) {
	// Add component
	if err := mem.AddComponent(input); err != nil {
		return nil, err
	}

	// Perform CVE detection
	if err := compDetect(mem, input.CPEs23, input.ID); err != nil {
		return nil, err
	}

	// Update Component after possible detections
	return mem.GetComponent(db.GetComponentInput{
		ID: input.ID,
	})
}

func UpdateComponent(mem *db.Memory, input db.UpdateComponentInput) (*model.Component, error) {
	// Update component
	if err := mem.UpdateComponent(input); err != nil {
		return nil, err
	}

	// Perform CVE detection
	if err := compDetect(mem, input.CPEs23, input.ID); err != nil {
		return nil, err
	}

	return mem.GetComponent(db.GetComponentInput{
		ID: input.ID,
	})
}

func DeleteComponent(mem *db.Memory, input db.DeleteComponentInput) (*model.Component, error) {
	// Pre-fetch component that will be deleted
	comp, err := mem.GetComponent(db.GetComponentInput{
		ID: input.ID,
	})
	if err != nil {
		return nil, err
	}
	// Delete component
	if err := mem.DeleteComponent(db.DeleteComponentInput{
		ID: input.ID,
	}); err != nil {
		return nil, err
	}
	return comp, nil
}

func compDetect(mem *db.Memory, cpes23 []string, compID string) error {
	// Shortcut if no cpes23
	if cpes23 == nil {
		return nil
	}

	// Get related CVEs
	vpMap := map[string]struct{}{}
	for _, cpe23 := range cpes23 {
		wfn, _ := naming.UnbindFS(cpe23)
		vpMap[wfn.GetString("vendor")+":"+wfn.GetString("product")] = struct{}{}
	}
	cves := []*model.CVE{}
	for vp := range vpMap {
		cves = append(cves, mem.QueryCVEs(db.QueryCVEInput{
			VP: &vp,
		})...)
	}

	// Run MDC1
	comp, _ := mem.GetComponent(db.GetComponentInput{
		ID: compID,
	})
	matchingCVEs := []db.UpdateComponentCVEsInput{}
	for _, cve := range cves {
		if detection.MDC1(comp, cve) {
			matchingCVEs = append(matchingCVEs, db.UpdateComponentCVEsInput{
				ID: cve.ID,
			})
		}
	}

	// Update Component to add matching CVEs
	if err := mem.UpdateComponent(db.UpdateComponentInput{
		ID:   compID,
		CVEs: matchingCVEs,
	}); err != nil {
		return err
	}
	return nil
}
