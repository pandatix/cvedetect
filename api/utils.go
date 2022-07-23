package api

import "encoding/json"

// Cast translates src into dst using standard JSON
// marshal/unmarshal operations.
func Cast(src any, dst any) {
	b, _ := json.Marshal(src)
	_ = json.Unmarshal(b, &dst)
}
