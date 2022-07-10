package mutation

import "github.com/knqyf263/go-cpe/naming"

func getVP(cpe23 string) string {
	wfn, err := naming.UnbindFS(cpe23)
	if err != nil {
		panic(err)
	}
	return wfn.GetString("vendor") + ":" + wfn.GetString("product")
}
