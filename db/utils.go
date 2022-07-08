package db

// containsWildcard returns true if str contains a wildcard,
// according to the NIST-IR 7695 "CPE v2.3 Naming specification".
func containsWildcard(str string) bool {
	for i := 0; i < len(str); i++ {
		if str[i] == '\\' {
			i++
			continue
		}
		if str[i] == '*' || str[i] == '?' {
			return true
		}
	}
	return false
}

// splits vp around the ":", but not "\:" which is a valid char
// in NIST-IR 7695 "CPE v2.3 Naming specification" Figure 5-3,
// ABNF rule avstring.
func splitVP(vp string) (string, string) {
	for i := 0; i < len(vp); i++ {
		if vp[i] == '\\' {
			i++
			continue
		}
		if vp[i] == ':' {
			return vp[:i], vp[i+1:]
		}
	}
	panic("can't find cut position")
}
