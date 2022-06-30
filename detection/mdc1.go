package detection

import (
	"strings"

	version "github.com/hashicorp/go-version"
	"github.com/knqyf263/go-cpe/matching"
	"github.com/knqyf263/go-cpe/naming"
	"github.com/pandatix/cvedetect/model"
)

// MDC1 performs a CVE's configurtion check for a Component using
// the MDC1 [TES-22] algorithm. As it is based on a CPE and
// configurations, it wraps the actual algorithm.
// Such check should be performed on each node for an alone-vulnerable
// detection, before a tree mode using the MDCN [TES-22] algorithm.
func MDC1(comp *model.Component, cve *model.CVE) bool {
	for _, conf := range cve.Configurations {
		pos, _ := mdc1(comp.CPE23, conf)
		if pos.Children != nil || pos.Matchers != nil {
			return true
		}
	}
	return false
}

func mdc1(cpe23 string, conf *model.Node) (pos, neg *Node) {
	// Build root
	pos = &Node{
		Operator: conf.Operator,
	}
	neg = &Node{
		Operator: conf.Operator,
	}

	// Select node/leaf mode
	if len(conf.Children) != 0 {
		// This part is not handled by MDC1
		return pos, neg
	} else {
		// Leaf mode => evaluate matching
		pos.Matchers = []*Matcher{}
		neg.Matchers = []*Matcher{}
		for _, cpeMatch := range conf.CPEMatches {
			matcher := &Matcher{
				SuperCPE23:            cpeMatch.CPE23,
				SubCPE23:              cpe23,
				VersionStartIncluding: cpPtrValue(cpeMatch.VersionStartIncluding),
				VersionStartExcluding: cpPtrValue(cpeMatch.VersionStartExcluding),
				VersionEndIncluding:   cpPtrValue(cpeMatch.VersionEndIncluding),
				VersionEndExcluding:   cpPtrValue(cpeMatch.VersionEndExcluding),
			}
			if matches(cpe23, cpeMatch) {
				pos.Matchers = append(pos.Matchers, matcher)
			} else {
				neg.Matchers = append(neg.Matchers, matcher)
			}
		}
	}

	// Inverse positive and negative paths if needed
	if conf.Negate != nil && *conf.Negate {
		pos, neg = neg, pos
	}

	// Flush remaining empty lists
	flush(pos)
	flush(neg)

	return pos, neg
}

// matches returns wether the given cpe23 matches the CPEMatch,
// and a match circuit built for this.
func matches(cpe23 string, cpeMatch *model.CPEMatch) bool {
	subWfn, _ := naming.UnbindFS(cpe23)
	supWfn, _ := naming.UnbindFS(cpeMatch.CPE23)

	if matching.IsSuperset(supWfn, subWfn) {
		// Build version interval
		scstr := ""
		if cpeMatch.VersionStartIncluding != nil {
			scstr = ">= " + *cpeMatch.VersionStartIncluding
		}
		if cpeMatch.VersionStartExcluding != nil {
			scstr = "> " + *cpeMatch.VersionStartExcluding
		}
		ecstr := ""
		if cpeMatch.VersionEndIncluding != nil {
			ecstr = "<= " + *cpeMatch.VersionEndIncluding
		}
		if cpeMatch.VersionEndExcluding != nil {
			ecstr = "< " + *cpeMatch.VersionEndExcluding
		}

		// Check if it is necessary to check for interval inclusion
		if scstr == "" && ecstr == "" {
			// => No version boundary to check => supersets only
			return cpeMatch.Vulnerable
		}

		// Build constraint string
		cstr := ""
		if scstr != "" {
			cstr = scstr
			if ecstr != "" {
				cstr += " , " + ecstr
			}
		} else {
			if ecstr != "" {
				cstr = ecstr
			}
		}

		// Check if included in version interval
		ctr, err := version.NewConstraint(cstr)
		if err != nil {
			// XXX may increase false rate
			return false
		}
		// XXX workaround as knqyf263 implemented a different "flavour" of the NIST-IR 7695... => should not try to escape characters, only validate
		// -> Should not escape inputs, must be quoted by the NVD / user
		rv := subWfn.GetString("version")
		rv = strings.ReplaceAll(rv, "\\", "")
		v, err := version.NewVersion(rv)
		if err != nil {
			// XXX may increase false rate
			return false
		}
		return ctr.Check(v) && cpeMatch.Vulnerable
	}
	return false
}

func flush(node *Node) {
	if len(node.Children) == 0 {
		node.Children = nil
	}
	if len(node.Matchers) == 0 {
		node.Matchers = nil
	}
}

func cpPtrValue[T any](t *T) *T {
	if t == nil {
		return nil
	}
	cpT := *t
	return &cpT
}
