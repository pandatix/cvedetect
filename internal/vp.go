package internal

func GetVP(cpe23 string) string {
	c := cpe23[len("cpe:2.3:a:"):]
	f := false
	for i := 0; i < len(c); i++ {
		if c[i] == '\\' {
			i++
			continue
		}
		if c[i] == ':' {
			if f {
				return c[:i]
			}
			f = true
		}
	}
	// This should not happen
	panic("vp couple not found in CPE v2.3 " + cpe23)
}
