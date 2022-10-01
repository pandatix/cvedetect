package internal_test

import (
	"testing"

	"github.com/pandatix/cvedetect/internal"
)

var Gvp string

func BenchmarkGetVP(b *testing.B) {
	cpe23 := "cpe:2.3:a:gitea\\:other:gitea:1.16.6:*:*:*:*:*:*:*"
	var vp string
	for i := 0; i < b.N; i++ {
		internal.GetVP(cpe23)
	}
	Gvp = vp
}
