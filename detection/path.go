package detection

import (
	"errors"
	"strings"

	"github.com/knqyf263/go-cpe/naming"
)

var (
	ErrTooShortMatcher = errors.New("too short matcher string")
	ErrTooShortNode    = errors.New("too short node string")
	ErrInvalidBounds   = errors.New("invalid surrounding bounds")
	ErrInvalidContent  = errors.New("invalid matcher content")
	ErrMalformedGroup  = errors.New("malformed groups")
	ErrMalformedTree   = errors.New("malformed tree structure: have children and matches")
)

func ParseNode(input string) (*Node, error) {
	// Check bounds
	if len(input) < 2 {
		return nil, ErrTooShortNode
	}
	if input[0] != '(' || input[len(input)-1] != ')' {
		return nil, ErrInvalidBounds
	}
	node := &Node{}

	// Extract operator
	switch input[1] {
	case '|':
		node.Operator = "OR"
	case '&':
		node.Operator = "AND"
	default:
		return nil, ErrInvalidContent
	}

	// Focus on bounded groups
	input = input[2 : len(input)-1]
	grps, err := parseGroups(input)
	if err != nil {
		return nil, err
	}
	children := []*Node{}
	matchers := []*Matcher{}
	for _, grp := range grps {
		// Test if grp is a Node
		child, err := ParseNode(grp)
		if err == nil {
			children = append(children, child)
			continue
		}
		// If not a Node, must be a Matcher
		matcher, err := ParseMatcher(grp)
		if err != nil {
			return nil, err
		}
		matchers = append(matchers, matcher)
	}

	// Check tree
	// => Can't have children and matchers at same time
	if len(children) != 0 && len(matchers) != 0 {
		return nil, ErrMalformedTree
	}
	node.Children = children
	node.Matchers = matchers
	if len(node.Children) == 0 {
		node.Children = nil
	}
	if len(node.Matchers) == 0 {
		node.Matchers = nil
	}

	return node, nil
}

// (          -> malformed groups
// ()         -> ()
// ()()       -> () ()
// (()())     -> (()())
// (())(()()) -> (()) (()())
func parseGroups(input string) ([]string, error) {
	grps := []string{}
	curr := ""
	b := 0
	escaped := false
	for i := 0; i < len(input); i++ {
		switch input[i] {
		case '(':
			if !escaped {
				b++
			}
		case ')':
			if !escaped {
				b--
			}
		}
		curr += string(input[i])
		if b == 0 {
			grps = append(grps, curr)
			curr = ""
		}
		escaped = false
		if input[i] == '\\' {
			escaped = true
		}
	}
	if curr != "" {
		return nil, ErrMalformedGroup
	}
	return grps, nil
}

// ParseMatcher parses a single Matcher string and returns an object
// representing it, or an error.
func ParseMatcher(input string) (*Matcher, error) {
	// Check bounds
	if len(input) < 2 {
		return nil, ErrTooShortMatcher
	}
	if input[0] != '(' || input[len(input)-1] != ')' {
		return nil, ErrInvalidBounds
	}

	// Extract sectors
	input = input[1 : len(input)-1]
	sectors := strings.Split(input, " , ")
	if len(sectors) != 3 {
		return nil, ErrInvalidContent
	}
	matcher := &Matcher{}

	// Parse first sector
	pts := strings.Split(sectors[0], " ")
	if len(pts) != 4 { // 4 because "<vulnerable> <supercpe> incl <subcpe>"
		return nil, ErrInvalidContent
	}
	// => Vulnerable
	switch pts[0] {
	case "v":
		matcher.Vulnerable = true
	case "i":
		matcher.Vulnerable = false
	default:
		return nil, ErrInvalidContent
	}
	// => SuperCPE23
	if _, err := naming.UnbindFS(pts[1]); err != nil {
		return nil, ErrInvalidContent
	}
	matcher.SuperCPE23 = pts[1]
	// => incl
	if pts[2] != "incl" {
		return nil, ErrInvalidContent
	}
	// => SubCPE23
	if _, err := naming.UnbindFS(pts[3]); err != nil {
		return nil, ErrInvalidContent
	}
	matcher.SubCPE23 = pts[3]

	// Parse second sector (start versions)
	pts = strings.Split(sectors[1], " ")
	if len(pts) == 1 {
		if pts[0] != "" {
			return nil, ErrInvalidContent
		}
	} else {
		if len(pts) != 2 {
			return nil, ErrInvalidContent
		}
		switch pts[1] {
		case "<":
			matcher.VersionStartExcluding = &pts[0]
		case "<=":
			matcher.VersionStartIncluding = &pts[0]
		default:
			return nil, ErrInvalidContent
		}
	}

	// Parse third sector (end versions)
	pts = strings.Split(sectors[2], " ")
	if len(pts) == 1 {
		if pts[0] != "" {
			return nil, ErrInvalidContent
		}
	} else {
		if len(pts) != 2 {
			return nil, ErrInvalidContent
		}
		switch pts[0] {
		case "<":
			matcher.VersionEndExcluding = &pts[1]
		case "<=":
			matcher.VersionEndIncluding = &pts[1]
		default:
			return nil, ErrInvalidContent
		}
	}

	return matcher, nil
}

// Node represents a circuit path of a CVE configuration.
// It could be used to explain what matched, or what did not.
// Remember that it does not handle the semantic of effectively
// vulnerable or not, as it is only a tool to represent wether it
// matched or not. Such semantic is handled by how the Node is used.
// It could be used to perform tracability on detections.
// It looks like a NVD configuration, because it represents an
// evaluation of a circuit.
// The root of a Node tree is called a Circuit.
type Node struct {
	Operator string
	Children []*Node
	Matchers []*Matcher
}

func (n Node) String() string {
	s := ""
	// Set operator
	if n.Operator == "OR" {
		s += "|"
	} else {
		s += "&"
	}
	// Build content
	if len(n.Children) != 0 {
		// Node mode
		for _, child := range n.Children {
			s += child.String()
		}
	} else {
		// Leaf mode
		for _, matcher := range n.Matchers {
			s += matcher.String()
		}
	}
	return "(" + s + ")"
}

// Matcher defines a single-node matching explanation.
// In case it is used to represent a CVE-Asset match,
// it explains that the SuperCPE23 contains the SubCPE23,
// and if version bounds are defined, why.
type Matcher struct {
	// SuperCPE23 is the CPE v2.3 containing the SubCPE23.
	SuperCPE23 string
	// SubCPE23 is the CPE v2.3 that is contained by SuperCPE23.
	// As it is defined, it is the Asset one. This imply that
	// the actual version used for bound check is stored in it.
	SubCPE23 string

	// Vulnerable defines whether this Matcher is one of the
	// vulnerable one or not.
	// If true, it implies that this Matcher triggered a part or
	// all of the detection.
	// This concept does not exist in MDC1, as the notion of
	// context does not exist too.
	Vulnerable bool

	// The following defines the version bounds in which you must
	// find the SubCPE23's version.

	VersionStartIncluding *string
	VersionStartExcluding *string
	VersionEndIncluding   *string
	VersionEndExcluding   *string
}

func (m Matcher) String() string {
	s := ""

	// Set first section
	if m.Vulnerable {
		s += "v "
	} else {
		s += "i "
	}
	s += m.SuperCPE23 + " incl " + m.SubCPE23 + " , "

	// XXX this workaround is due to NIST-IR 7695 that escapes dot, and necessary for readibility and version assetarison
	wfn, _ := naming.UnbindFS(m.SubCPE23)
	ver := wfn.GetString("version")
	ver = strings.ReplaceAll(ver, "\\.", ".")

	// Set version bounds sections (second and third)
	startB := startBounds(m.VersionStartIncluding, m.VersionStartExcluding, ver)
	endB := endBounds(m.VersionEndIncluding, m.VersionEndExcluding, ver)
	s += startB + " , " + endB

	// Output in boundaries
	return "(" + s + ")"
}

func startBounds(inc, exc *string, ver string) string {
	if inc != nil {
		return *inc + " <="
	}
	if exc != nil {
		return *exc + " <"
	}
	return ""
}

func endBounds(inc, exc *string, ver string) string {
	if inc != nil {
		return "<= " + *inc
	}
	if exc != nil {
		return "< " + *exc
	}
	return ""
}
