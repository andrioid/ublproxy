package blocklist

import "strings"

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
// for the given domain.
func (r *ElementHideRule) appliesTo(domain string) bool {
	domain = strings.ToLower(domain)

	// Check exclude domains first
	for _, d := range r.ExcludeDomains {
		if domainMatchesOrIsSubdomain(domain, d) {
			return false
		}
	}

	// If include domains are specified, domain must match one of them
	if len(r.IncludeDomains) > 0 {
		for _, d := range r.IncludeDomains {
			if domainMatchesOrIsSubdomain(domain, d) {
				return true
			}
		}
		return false
	}

	// No domain restrictions — applies to all domains
	return true
}

// CSSForDomain returns a CSS stylesheet that hides all elements matching
// the element hiding rules for the given domain. Returns empty string if
// no rules apply. Safe to call on a nil receiver.
func (rs *RuleSet) CSSForDomain(domain string) string {
	if rs == nil {
		return ""
	}

	// Collect applicable selectors
	var selectors []string
	for _, rule := range rs.elemHideRules {
		if rule.Exception || !rule.appliesTo(domain) {
			continue
		}

		// Check if an exception rule overrides this selector for this domain
		excepted := false
		for _, exc := range rs.elemHideRules {
			if exc.Exception && exc.Selector == rule.Selector && exc.appliesTo(domain) {
				excepted = true
				break
			}
		}
		if excepted {
			continue
		}

		selectors = append(selectors, rule.Selector)
	}

	if len(selectors) == 0 {
		return ""
	}

	return strings.Join(selectors, ",\n") + " {\n  display: none !important;\n}\n"
}
