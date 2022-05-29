package db

import "fmt"

type Key string

var (
	KeyCVE       Key = "cve"
	KeyComponent Key = "component"
)

// ErrAlreadyExist is returned when the in-memory DB already
// know an element of value V for the type given its key.
type ErrAlreadyExist struct {
	K Key
	V string
}

func (err ErrAlreadyExist) Error() string {
	return fmt.Sprintf("object of type %s already exist for value %s", err.K, err.V)
}

var _ error = (*ErrAlreadyExist)(nil)

// ErrNotExist is returned when the in-memory DB does not
// know an element of value V for the type given its key.
type ErrNotExist struct {
	K Key
	V string
}

func (err ErrNotExist) Error() string {
	return fmt.Sprintf("object of type %s does not exist for value %s", err.K, err.V)
}

var _ error = (*ErrNotExist)(nil)
