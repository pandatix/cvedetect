package query

import (
	"github.com/pandatix/cvedetect/db"
	"github.com/pandatix/cvedetect/model"
)

func GetComponent(mem *db.Memory, input db.GetComponentInput) (*model.Component, error) {
	return mem.GetComponent(input)
}

func QueryComponents(mem *db.Memory, input db.QueryComponentInput) ([]*model.Component, error) {
	return mem.QueryComponents(input), nil
}
