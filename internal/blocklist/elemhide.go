package blocklist

import (
	"strings"
	"sync"
)

// ElementHiding holds the CSS for hiding ad elements on a specific domain.
// All selectors are combined into a single display:none stylesheet.
type ElementHiding struct {
	CSS               string   // display:none CSS for all selectors (may be empty)
	Selectors         []string // individual CSS selectors before joining
	GenericSelectors  []string // selectors with no domain constraint (##.ad)
	SpecificSelectors []string // selectors with domain constraint (example.com##.ad)
}

// ElementHideRule represents a CSS element hiding rule from an adblock filter.
type ElementHideRule struct {
	Selector       string   // CSS selector (e.g. ".ad-banner")
	IncludeDomains []string // domains where this rule applies (empty = all)
	ExcludeDomains []string // domains where this rule is excluded
	Exception      bool     // true for #@# rules (unhide)
}

// ScriptletRule represents a ##+js() scriptlet injection rule.
type ScriptletRule struct {
	Name           string   // scriptlet name (e.g. "set-constant", "nowebrtc")
	Args           []string // arguments after the name
	IncludeDomains []string // domains where this rule applies (empty = all)
	ExcludeDomains []string // domains where this rule is excluded
	Exception      bool     // true for #@#+js() rules
}

// parseScriptletRule parses a ##+js() or #@#+js() line into a ScriptletRule.
// Returns nil if the line is not a scriptlet injection rule.
func parseScriptletRule(line string) *ScriptletRule {
	var exception bool
	var idx int
	var domainPart string

	if i := strings.Index(line, "#@#+js("); i >= 0 {
		exception = true
		idx = i
		domainPart = line[:idx]
	} else if i := strings.Index(line, "##+js("); i >= 0 {
		idx = i
		domainPart = line[:idx]
	} else {
		return nil
	}

	// Extract the js() content
	var jsStart int
	if exception {
		jsStart = idx + len("#@#+js(")
	} else {
		jsStart = idx + len("##+js(")
	}

	if !strings.HasSuffix(line, ")") {
		return nil
	}
	content := line[jsStart : len(line)-1]

	// Parse name and arguments (comma-separated)
	parts := strings.SplitN(content, ",", -1)
	name := strings.TrimSpace(parts[0])
	if name == "" {
		return nil
	}

	var args []string
	for _, p := range parts[1:] {
		args = append(args, strings.TrimSpace(p))
	}

	rule := &ScriptletRule{
		Name:      name,
		Args:      args,
		Exception: exception,
	}

	if domainPart != "" {
		for _, d := range strings.Split(domainPart, ",") {
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

	return rule
}

// appliesTo returns true if this scriptlet rule should be applied
// for the given domain. The domain must already be lowercased.
func (r *ScriptletRule) appliesTo(domain string) bool {
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

// isScriptletLine returns true if the line is a ##+js() or #@#+js() scriptlet rule.
func isScriptletLine(line string) bool {
	return strings.Contains(line, "##+js(") || strings.Contains(line, "#@#+js(")
}

// parseElementHideRule parses a line containing ## or #@# into an
// ElementHideRule. Returns nil if the line is not a valid element hiding rule.
func parseElementHideRule(line string) *ElementHideRule {
	// Scriptlet injection lines (##+js, #@#+js) are handled separately
	if isScriptletLine(line) {
		return nil
	}

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
	var genericSels, specificSels []string

	for _, rule := range rs.elemHideRules {
		if rule.Exception || !rule.appliesTo(domain) {
			continue
		}
		if rs.elemHideIdx.isExcepted(rule.Selector, domain) {
			continue
		}
		if len(rule.IncludeDomains) == 0 && len(rule.ExcludeDomains) == 0 {
			genericSels = append(genericSels, rule.Selector)
		} else {
			specificSels = append(specificSels, rule.Selector)
		}
	}

	allSels := make([]string, 0, len(genericSels)+len(specificSels))
	allSels = append(allSels, genericSels...)
	allSels = append(allSels, specificSels...)

	if len(allSels) == 0 {
		return nil
	}

	css := strings.Join(allSels, ",\n") + " {\n  display: none !important;\n}\n"
	return &ElementHiding{
		CSS:               css,
		Selectors:         allSels,
		GenericSelectors:  genericSels,
		SpecificSelectors: specificSels,
	}
}

// ScriptletsForDomain returns the scriptlet rules applicable to a domain,
// excluding those suppressed by #@#+js() exceptions.
// Safe to call on a nil receiver (returns nil).
func (rs *RuleSet) ScriptletsForDomain(domain string) []*ScriptletRule {
	if rs == nil {
		return nil
	}

	domain = strings.ToLower(domain)

	// Build a set of excepted scriptlet names for this domain
	excepted := make(map[string]bool)
	for _, rule := range rs.scriptletRules {
		if rule.Exception && rule.appliesTo(domain) {
			excepted[rule.Name] = true
		}
	}

	var result []*ScriptletRule
	for _, rule := range rs.scriptletRules {
		if rule.Exception {
			continue
		}
		if !rule.appliesTo(domain) {
			continue
		}
		if excepted[rule.Name] {
			continue
		}
		result = append(result, rule)
	}

	return result
}
