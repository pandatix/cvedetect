package detection

import "github.com/knqyf263/go-cpe/naming"

// Node represents a circuit path of a CVE configuration.
// It could be used to explain what matched, or what did not.
// It is defined in [TES-22].
// Remember that it does not handle the semantic of effectively
// vulnerable or not, as it is only a tool to represent wether it
// matched or not. Such semantic is handled by how the Node is used.
// It could be used to perform tracability on detections.
// It looks like a NVD configuration, because it represents an
// evaluation of a circuit.
type Node struct {
	Operator string
	Children []*Node
	Matchers []*Matcher
}

func (n Node) String() string {
	s := "("
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
	return s + ")"
}

// Matcher defines a single-node matching explanation.
// In case it is used to represent a CVE-Component match,
// it explains that the SuperCPE23 contains the SubCPE23,
// and if version bounds are defined, why.
type Matcher struct {
	// SuperCPE23 is the CPE v2.3 containing the SubCPE23.
	SuperCPE23 string
	// SubCPE23 is the CPE v2.3 that is contained by SuperCPE23.
	// As it is defined, it is the Component one. This imply that
	// the actual version used for bound check is stored in it.
	SubCPE23 string

	// The following are directly inherited from the NVD.

	VersionStartIncluding *string
	VersionStartExcluding *string
	VersionEndIncluding   *string
	VersionEndExcluding   *string
}

func (m Matcher) String() string {
	s := "(" + m.SuperCPE23 + " incl " + m.SubCPE23 + " , "
	// Build inferior bound
	infB := ""
	if m.VersionStartIncluding != nil {
		infB = *m.VersionStartIncluding + " <= "
	}
	if m.VersionStartExcluding != nil {
		infB = *m.VersionStartExcluding + " < "
	}
	// Build superior bound
	supB := ""
	if m.VersionEndIncluding != nil {
		supB = " <= " + *m.VersionEndIncluding
	}
	if m.VersionEndExcluding != nil {
		supB = " < " + *m.VersionEndExcluding
	}
	if infB != "" || supB != "" {
		// Build the version part
		wfn, _ := naming.UnbindFS(m.SubCPE23)
		s += infB + wfn.GetString("version") + supB
	}
	// Check if
	return s + ")"
}
