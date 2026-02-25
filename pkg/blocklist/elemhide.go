package blocklist

import (
	"strings"
	"sync"
)

// ElementHideRule represents a CSS element hiding rule from an adblock filter.
type ElementHideRule struct {
	Selector       string   // CSS selector (e.g. ".ad-banner")
	IncludeDomains []string // domains where this rule applies (empty = all)
	ExcludeDomains []string // domains where this rule is excluded
	Exception      bool     // true for #@# rules (unhide)
}

// parseElementHideRule parses a line containing ## or #@# into an
// ElementHideRule. Returns nil if the line is not a valid element hiding rule.
func parseElementHideRule(line string) *ElementHideRule {
	// Try #@# (exception) first since it contains ##
	if idx := strings.Index(line, "#@#"); idx >= 0 {
		selector := strings.TrimSpace(line[idx+3:])
		if selector == "" {
			return nil
		}
		rule := &ElementHideRule{
			Selector:  selector,
			Exception: true,
		}
		if idx > 0 {
			parseDomainList(line[:idx], rule)
		}
		return rule
	}

	// Extended selectors (#?#, #$#) are not supported
	if strings.Contains(line, "#?#") || strings.Contains(line, "#$#") {
		return nil
	}

	if idx := strings.Index(line, "##"); idx >= 0 {
		selector := strings.TrimSpace(line[idx+2:])
		if selector == "" {
			return nil
		}
		rule := &ElementHideRule{
			Selector: selector,
		}
		if idx > 0 {
			parseDomainList(line[:idx], rule)
		}
		return rule
	}

	return nil
}

func parseDomainList(domainStr string, rule *ElementHideRule) {
	for _, d := range strings.Split(domainStr, ",") {
		d = strings.TrimSpace(strings.ToLower(d))
		if d == "" {
			continue
		}
		if strings.HasPrefix(d, "~") {
			rule.ExcludeDomains = append(rule.ExcludeDomains, d[1:])
		} else {
			rule.IncludeDomains = append(rule.IncludeDomains, d)
		}
	}
}

// appliesTo returns true if this element hiding rule should be applied
// for the given domain. The domain must already be lowercased.
func (r *ElementHideRule) appliesTo(domain string) bool {
	for _, d := range r.ExcludeDomains {
		if domainMatchesOrIsSubdomain(domain, d) {
			return false
		}
	}

	if len(r.IncludeDomains) > 0 {
		for _, d := range r.IncludeDomains {
			if domainMatchesOrIsSubdomain(domain, d) {
				return true
			}
		}
		return false
	}

	return true
}

// elemHideIndex provides fast lookup for element hiding exception rules
// by selector, and caches computed CSS per domain.
type elemHideIndex struct {
	// exceptions maps CSS selector -> list of exception rules for that selector
	exceptions map[string][]*ElementHideRule
	// cssCache stores computed CSS per domain (immutable after RuleSet loading)
	cssCache sync.Map
}

func newElemHideIndex() *elemHideIndex {
	return &elemHideIndex{
		exceptions: make(map[string][]*ElementHideRule),
	}
}

// addException indexes an element hiding exception rule by its selector.
func (idx *elemHideIndex) addException(rule *ElementHideRule) {
	idx.exceptions[rule.Selector] = append(idx.exceptions[rule.Selector], rule)
}

// isExcepted returns true if the selector is overridden by an exception
// rule for the given domain. The domain must already be lowercased.
func (idx *elemHideIndex) isExcepted(selector, domain string) bool {
	excRules := idx.exceptions[selector]
	for _, exc := range excRules {
		if exc.appliesTo(domain) {
			return true
		}
	}
	return false
}

// CSSForDomain returns a CSS stylesheet that hides all elements matching
// the element hiding rules for the given domain. Results are cached.
// Returns empty string if no rules apply. Safe to call on a nil receiver.
func (rs *RuleSet) CSSForDomain(domain string) string {
	if rs == nil || rs.elemHideIdx == nil {
		return ""
	}

	domain = strings.ToLower(domain)

	// Check cache
	if cached, ok := rs.elemHideIdx.cssCache.Load(domain); ok {
		return cached.(string)
	}

	css := rs.computeCSSForDomain(domain)
	rs.elemHideIdx.cssCache.Store(domain, css)
	return css
}

func (rs *RuleSet) computeCSSForDomain(domain string) string {
	var selectors []string
	for _, rule := range rs.elemHideRules {
		if rule.Exception || !rule.appliesTo(domain) {
			continue
		}
		if rs.elemHideIdx.isExcepted(rule.Selector, domain) {
			continue
		}
		selectors = append(selectors, rule.Selector)
	}

	if len(selectors) == 0 {
		return ""
	}

	return strings.Join(selectors, ",\n") + " {\n  display: none !important;\n}\n"
}
