package mutation_test

import (
	"time"
)

func timeParse(ts string) time.Time {
	t, err := time.Parse("2006-01-02T15:04Z", ts)
	if err != nil {
		panic(err)
	}
	return t
}

func ptr[T any](t T) *T {
	return &t
}
