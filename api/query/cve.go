package query

import (
	"github.com/pandatix/cvedetect/db"
	"github.com/pandatix/cvedetect/model"
)

func GetCVE(mem *db.Memory, input db.GetCVEInput) (*model.CVE, error) {
	return mem.GetCVE(input)
}

func QueryCVEs(mem *db.Memory, input db.QueryCVEInput) ([]*model.CVE, error) {
	return mem.QueryCVEs(input), nil
}
