// Copyright 2020 Authors of Hubble
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package filters

import (
	"fmt"
	"regexp"
	"strings"

	flowpb "github.com/cilium/cilium/api/v1/flow"
)

// A NodeNameFilter filters on node name. An empty NodeNameFilter matches all
// node names.
//
// NodeNameFilters are different to other filters as they are applied at the
// node level, not at the individual flow level.
//
// Node names are hostnames optionally prefixed by a cluster name and a slash,
// for example "k8s1" and "test-cluster/node01.company.com". Patterns match node
// names (hostnames) and are similar to filename globs, for example "k8s*" and
// "test-cluster/*.company.com". Literal lowercase letters, digits, hyphens,
// dots, and forward slashes match themselves. A literal "*" matches zero or
// more lowercase letters, digits, and hyphens (i.e. everything except a forward
// slash or a dot).  All other characters are invalid.
type NodeNameFilter struct {
	whitelistRegexp *regexp.Regexp
	blacklistRegexp *regexp.Regexp
}

// NewNodeNameFilter returns a new NodeNameFilter with whitelist and blacklist.
func NewNodeNameFilter(whitelist, blacklist []*flowpb.FlowFilter) (*NodeNameFilter, error) {
	whitelistRegexp, err := compileNodeNamePatterns(whitelist)
	if err != nil {
		return nil, err
	}
	blacklistRegexp, err := compileNodeNamePatterns(blacklist)
	if err != nil {
		return nil, err
	}

	// short path: if there are no filters then return nil to avoid an
	// allocation
	if whitelistRegexp == nil && blacklistRegexp == nil {
		return nil, nil
	}

	return &NodeNameFilter{
		whitelistRegexp: whitelistRegexp,
		blacklistRegexp: blacklistRegexp,
	}, nil
}

// Match returns true if f matches nodeName.
func (f *NodeNameFilter) Match(nodeName string) bool {
	if f == nil {
		return true
	}
	if f.whitelistRegexp != nil && !f.whitelistRegexp.MatchString(nodeName) {
		return false
	}
	if f.blacklistRegexp != nil && f.blacklistRegexp.MatchString(nodeName) {
		return false
	}
	return true
}

// compileNodeNamePatterns returns a regular expression equivalent to the node
// patterns in flowFilters. If flowFilters contains no node patterns then it
// returns nil.
func compileNodeNamePatterns(flowFilters []*flowpb.FlowFilter) (*regexp.Regexp, error) {
	sb := &strings.Builder{}
	sb.WriteString(`\A(`)
	n := 0
	for _, flowFilter := range flowFilters {
		for _, nodePattern := range flowFilter.GetNodeNames() {
			n++
			if n > 1 {
				sb.WriteByte('|')
			}
			if err := appendNodeNamePatternRegexp(sb, nodePattern); err != nil {
				return nil, err
			}
		}
	}
	if n == 0 {
		return nil, nil
	}
	sb.WriteString(`)\z`)
	return regexp.Compile(sb.String())
}

// appendNodeNamePatternRegexp appends the regular expression equivalent to
// nodePattern to sb.
func appendNodeNamePatternRegexp(sb *strings.Builder, nodeNamePattern string) error {
	for _, r := range nodeNamePattern {
		switch {
		case r == '.':
			sb.WriteString(`\.`)
		case r == '*':
			sb.WriteString(`[\-0-9a-z]*`)
		case r == '-':
			fallthrough
		case r == '/':
			fallthrough
		case '0' <= r && r <= '9':
			fallthrough
		case 'a' <= r && r <= 'z':
			sb.WriteRune(r)
		default:
			return fmt.Errorf("%q: invalid rune in node name pattern", r)
		}
	}
	return nil
}
