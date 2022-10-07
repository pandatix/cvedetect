package db

import (
	"reflect"
	"testing"
	"time"

	"github.com/pandatix/cvedetect/model"
	"github.com/stretchr/testify/assert"
)

var flag = "!!! MODIFIED !!!"
var timeTimeType = reflect.TypeOf(time.Time{})

func alter(obj any) {
	v := reflect.ValueOf(obj)
	alterValue(v)
}

func alterValue(v reflect.Value) {
	if v.Type() == timeTimeType && v.CanAddr() {
		tPtr := v.Addr().Interface().(*time.Time)
		t := tPtr.Add(time.Hour)
		*tPtr = t
		return
	}

	switch v.Kind() {
	case reflect.Pointer:
		if v.IsNil() {
			return
		}
		alterValue(v.Elem())

	case reflect.String:
		if !v.CanSet() {
			return
		}
		v.SetString(v.String() + flag)

	case reflect.Bool:
		if !v.CanSet() {
			return
		}
		v.SetBool(!v.Bool())

	case reflect.Int:
		if !v.CanSet() {
			return
		}
		v.SetInt(v.Int() + 1)

	case reflect.Struct:
		l := v.NumField()
		for i := 0; i < l; i++ {
			f := v.Field(i)
			alterValue(f)
		}

	case reflect.Slice:
		l := v.Len()
		for i := 0; i < l; i++ {
			f := v.Index(i)
			alterValue(f)
		}

		if v.CanSet() {
			t := v.Type().Elem()
			nv := reflect.Append(v, reflect.New(t).Elem())
			v.Set(nv)
		}
	}
}

func TestAlter(t *testing.T) {
	t.Parallel()

	var tests = map[string]struct {
		Object         any
		ExpectedObject any
	}{
		"asset": {
			Object: &model.Asset{
				ID:       "asset",
				Name:     "Asset",
				CPE23:    "cpe:2.3:a:fake:asset:*:*:*:*:*:*:*:*",
				Parents:  []*model.Asset{},
				Children: []*model.Asset{},
				CVEs:     []*model.CVE{},
			},
			ExpectedObject: &model.Asset{
				ID:       "asset" + flag,
				Name:     "Asset" + flag,
				CPE23:    "cpe:2.3:a:fake:asset:*:*:*:*:*:*:*:*" + flag,
				Parents:  []*model.Asset{nil},
				Children: []*model.Asset{nil},
				CVEs:     []*model.CVE{nil},
			},
		},
		"cve": {
			Object: &model.CVE{
				ID:              "cve",
				Description:     "This is a CVE.",
				PublicationDate: timeParse("2020-02-01T14:30Z"),
				LastUpdate:      timeParse("2020-02-01T14:30Z"),
				CVSS2Vector:     nil,
				CVSS3Vector:     nil,
				Configurations: []*model.Node{
					{
						Negate:   nil,
						Operator: "OR",
						Children: []*model.Node{},
						CPEMatches: []*model.CPEMatch{
							{
								Vulnerable:            true,
								CPE23:                 "cpe:2.3:a:fake:asset:*:*:*:*:*:*:*:*",
								VersionStartIncluding: nil,
								VersionStartExcluding: nil,
								VersionEndIncluding:   nil,
								VersionEndExcluding:   nil,
							},
						},
					},
				},
				Assets: []*model.Asset{},
				References: []*model.Reference{
					{
						URL:       "https://example.com",
						Refsource: "MISC",
						Tags:      []string{"Third Party Advisory"},
					},
				},
			},
			ExpectedObject: &model.CVE{
				ID:              "cve" + flag,
				Description:     "This is a CVE." + flag,
				PublicationDate: timeParse("2020-02-01T15:30Z"),
				LastUpdate:      timeParse("2020-02-01T15:30Z"),
				CVSS2Vector:     nil,
				CVSS3Vector:     nil,
				Configurations: []*model.Node{
					{
						Negate:   nil,
						Operator: "OR" + flag,
						Children: []*model.Node{nil},
						CPEMatches: []*model.CPEMatch{
							{
								Vulnerable:            false,
								CPE23:                 "cpe:2.3:a:fake:asset:*:*:*:*:*:*:*:*" + flag,
								VersionStartIncluding: nil,
								VersionStartExcluding: nil,
								VersionEndIncluding:   nil,
								VersionEndExcluding:   nil,
							}, nil,
						},
					}, nil,
				},
				Assets: []*model.Asset{nil},
				References: []*model.Reference{
					{
						Name:      flag,
						URL:       "https://example.com" + flag,
						Refsource: "MISC" + flag,
						Tags:      []string{"Third Party Advisory" + flag, ""},
					}, nil,
				},
			},
		},
		"slice-asset": {
			Object: []*model.Asset{
				{
					ID:       "asset",
					Name:     "Asset",
					CPE23:    "cpe:2.3:a:fake:asset:*:*:*:*:*:*:*:*",
					Parents:  []*model.Asset{},
					Children: []*model.Asset{},
					CVEs:     []*model.CVE{},
				},
			},
			ExpectedObject: []*model.Asset{
				{
					ID:       "asset" + flag,
					Name:     "Asset" + flag,
					CPE23:    "cpe:2.3:a:fake:asset:*:*:*:*:*:*:*:*" + flag,
					Parents:  []*model.Asset{nil},
					Children: []*model.Asset{nil},
					CVEs:     []*model.CVE{nil},
				},
			},
		},
	}

	for testname, tt := range tests {
		t.Run(testname, func(t *testing.T) {
			assert := assert.New(t)

			alter(tt.Object)

			assert.Equal(tt.ExpectedObject, tt.Object)
		})
	}
}
