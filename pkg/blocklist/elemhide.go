package blocklist

import (
	"strings"
	"sync"
)

// ElementHiding holds the CSS for hiding ad elements on a specific domain.
// All selectors are combined into a single display:none stylesheet.
type ElementHiding struct {
	CSS string // display:none CSS for all selectors (may be empty)
}

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
// by selector, and caches computed element hiding data per domain.
type elemHideIndex struct {
	// exceptions maps CSS selector -> list of exception rules for that selector
	exceptions map[string][]*ElementHideRule
	// cache stores computed ElementHiding per domain (immutable after RuleSet loading)
	cache sync.Map
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

// ElementHidingForDomain returns the element hiding CSS for the given domain.
// All applicable selectors are combined into a single display:none stylesheet.
// Results are cached. Safe to call on a nil receiver (returns nil).
func (rs *RuleSet) ElementHidingForDomain(domain string) *ElementHiding {
	if rs == nil || rs.elemHideIdx == nil {
		return nil
	}

	domain = strings.ToLower(domain)

	if cached, ok := rs.elemHideIdx.cache.Load(domain); ok {
		return cached.(*ElementHiding)
	}

	eh := rs.computeElementHiding(domain)
	rs.elemHideIdx.cache.Store(domain, eh)
	return eh
}

func (rs *RuleSet) computeElementHiding(domain string) *ElementHiding {
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
		return nil
	}

	css := strings.Join(selectors, ",\n") + " {\n  display: none !important;\n}\n"
	return &ElementHiding{CSS: css}
}
