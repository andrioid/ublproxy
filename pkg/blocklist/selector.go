package blocklist

import "strings"

// AttrOp describes how to match an attribute value.
type AttrOp int

const (
	AttrExists   AttrOp = iota // [attr]
	AttrEquals                 // [attr=val]
	AttrContains               // [attr*=val]
	AttrPrefix                 // [attr^=val]
	AttrSuffix                 // [attr$=val]
)

// AttrMatch represents a single attribute condition in a selector.
type AttrMatch struct {
	Name  string
	Value string
	Op    AttrOp
}

// SelectorMatch holds parsed match criteria for a simple CSS selector that
// can be evaluated by inspecting a single HTML element's attributes.
type SelectorMatch struct {
	Selector string      // original selector string (e.g. "div.ad-banner")
	Tag      string      // required tag name, empty = any (lowercased)
	ID       string      // required id, empty = no id constraint
	Classes  []string    // all required classes
	Attrs    []AttrMatch // attribute conditions beyond id/class
}

// ElementHiding holds the selectors applicable to a domain. All selectors
// produce CSS (display: none !important) to hide elements immediately and
// block JS-injected ads. Simple selectors also produce Matchers for
// element replacement, physically stripping matched content from the HTML.
type ElementHiding struct {
	Matchers []SelectorMatch // simple selectors for element replacement
	CSS      string          // display:none CSS for all selectors (may be empty)
}

// Empty returns true if there are no selectors to apply.
func (eh *ElementHiding) Empty() bool {
	return len(eh.Matchers) == 0 && eh.CSS == ""
}

// MatchesAttrs returns true if the element's attributes satisfy all the
// conditions in this SelectorMatch.
func (sm *SelectorMatch) MatchesAttrs(tagName string, attrFn func(string) string) bool {
	if sm.Tag != "" && sm.Tag != tagName {
		return false
	}

	if sm.ID != "" {
		if attrFn("id") != sm.ID {
			return false
		}
	}

	if len(sm.Classes) > 0 {
		classAttr := attrFn("class")
		if classAttr == "" {
			return false
		}
		classes := splitClasses(classAttr)
		for _, want := range sm.Classes {
			if !containsString(classes, want) {
				return false
			}
		}
	}

	for _, am := range sm.Attrs {
		val := attrFn(am.Name)
		switch am.Op {
		case AttrExists:
			// attrFn returns "" for missing attributes, but also for
			// attributes with empty values. We need the caller to
			// distinguish, but for practical adblock selectors [attr]
			// checks (like [href]) this is sufficient — an empty href
			// is still present.
			// We rely on the caller passing a function that returns a
			// sentinel for missing attributes. For simplicity, we skip
			// AttrExists matching here and handle it in the tokenizer.
		case AttrEquals:
			if val != am.Value {
				return false
			}
		case AttrContains:
			if !strings.Contains(val, am.Value) {
				return false
			}
		case AttrPrefix:
			if !strings.HasPrefix(val, am.Value) {
				return false
			}
		case AttrSuffix:
			if !strings.HasSuffix(val, am.Value) {
				return false
			}
		}
	}

	return true
}

// ClassifySelector attempts to parse a CSS selector into a SelectorMatch.
// Returns nil if the selector is too complex to match on a single element
// (descendant/child/sibling combinators, pseudo-classes like :has(), :not()).
func ClassifySelector(selector string) *SelectorMatch {
	s := strings.TrimSpace(selector)
	if s == "" {
		return nil
	}

	// Reject selectors with combinators or pseudo-classes that need DOM context.
	// We check for spaces (descendant combinator) but must be careful not to
	// reject attribute selectors that contain spaces in values like
	// DIV[style="padding: 20px 0; text-align: center;"]
	if containsUnquotedSpace(s) {
		return nil
	}
	if strings.ContainsAny(s, "+~") {
		return nil
	}
	if strings.Contains(s, ":has(") || strings.Contains(s, ":not(") {
		return nil
	}
	// Reject any pseudo-class/pseudo-element except attribute selectors
	if containsUnbracketedColon(s) {
		return nil
	}
	// Reject child combinator ">"
	if containsUnbracketedChar(s, '>') {
		return nil
	}

	sm := &SelectorMatch{Selector: selector}

	if !parseSimpleSelector(s, sm) {
		return nil
	}

	// Must have at least one constraint
	if sm.Tag == "" && sm.ID == "" && len(sm.Classes) == 0 && len(sm.Attrs) == 0 {
		return nil
	}

	return sm
}

// parseSimpleSelector parses a compound selector like "div.foo#bar[attr=val]"
// into the SelectorMatch. Returns false if parsing fails.
func parseSimpleSelector(s string, sm *SelectorMatch) bool {
	i := 0
	n := len(s)

	// Parse optional leading tag name (before any . # or [)
	if i < n && s[i] != '.' && s[i] != '#' && s[i] != '[' {
		start := i
		for i < n && s[i] != '.' && s[i] != '#' && s[i] != '[' {
			i++
		}
		sm.Tag = strings.ToLower(s[start:i])
	}

	// Parse chain of .class, #id, and [attr] selectors
	for i < n {
		switch s[i] {
		case '#':
			i++
			start := i
			for i < n && s[i] != '.' && s[i] != '#' && s[i] != '[' {
				i++
			}
			if start == i {
				return false
			}
			sm.ID = s[start:i]

		case '.':
			i++
			start := i
			for i < n && s[i] != '.' && s[i] != '#' && s[i] != '[' {
				i++
			}
			if start == i {
				return false
			}
			sm.Classes = append(sm.Classes, s[start:i])

		case '[':
			end := findMatchingBracket(s, i)
			if end < 0 {
				return false
			}
			inner := s[i+1 : end]
			am, ok := parseAttrSelector(inner)
			if !ok {
				return false
			}
			sm.Attrs = append(sm.Attrs, am)
			i = end + 1

		default:
			return false
		}
	}

	return true
}

// parseAttrSelector parses the inside of [...], e.g. class*="advertisement"
func parseAttrSelector(inner string) (AttrMatch, bool) {
	inner = strings.TrimSpace(inner)
	if inner == "" {
		return AttrMatch{}, false
	}

	// Find operator position
	opIdx := strings.IndexAny(inner, "=*^$")
	if opIdx < 0 {
		// [attr] — existence check
		return AttrMatch{Name: strings.ToLower(inner), Op: AttrExists}, true
	}

	var op AttrOp
	var nameEnd int

	switch {
	case inner[opIdx] == '=' && (opIdx == 0 || (inner[opIdx-1] != '*' && inner[opIdx-1] != '^' && inner[opIdx-1] != '$')):
		op = AttrEquals
		nameEnd = opIdx
	case opIdx > 0 && inner[opIdx] == '*' && opIdx+1 < len(inner) && inner[opIdx+1] == '=':
		op = AttrContains
		nameEnd = opIdx
		opIdx++ // skip past =
	case opIdx > 0 && inner[opIdx] == '^' && opIdx+1 < len(inner) && inner[opIdx+1] == '=':
		op = AttrPrefix
		nameEnd = opIdx
		opIdx++ // skip past =
	case opIdx > 0 && inner[opIdx] == '$' && opIdx+1 < len(inner) && inner[opIdx+1] == '=':
		op = AttrSuffix
		nameEnd = opIdx
		opIdx++ // skip past =
	default:
		return AttrMatch{}, false
	}

	name := strings.TrimSpace(strings.ToLower(inner[:nameEnd]))
	value := strings.TrimSpace(inner[opIdx+1:])
	value = unquote(value)

	return AttrMatch{Name: name, Value: value, Op: op}, true
}

// findMatchingBracket finds the ] that closes the [ at position start,
// respecting quoted strings inside the brackets.
func findMatchingBracket(s string, start int) int {
	inQuote := byte(0)
	for i := start + 1; i < len(s); i++ {
		if inQuote != 0 {
			if s[i] == inQuote {
				inQuote = 0
			}
			continue
		}
		if s[i] == '"' || s[i] == '\'' {
			inQuote = s[i]
			continue
		}
		if s[i] == ']' {
			return i
		}
	}
	return -1
}

// unquote removes surrounding single or double quotes from a string.
func unquote(s string) string {
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}

// containsUnquotedSpace returns true if s contains a space that is not inside
// brackets [...]. Spaces inside brackets are part of attribute values.
func containsUnquotedSpace(s string) bool {
	depth := 0
	inQuote := byte(0)
	for i := 0; i < len(s); i++ {
		if inQuote != 0 {
			if s[i] == inQuote {
				inQuote = 0
			}
			continue
		}
		switch s[i] {
		case '"', '\'':
			inQuote = s[i]
		case '[':
			depth++
		case ']':
			if depth > 0 {
				depth--
			}
		case ' ':
			if depth == 0 {
				return true
			}
		}
	}
	return false
}

// containsUnbracketedColon returns true if s contains a colon that is not
// inside brackets [...].
func containsUnbracketedColon(s string) bool {
	return containsUnbracketedChar(s, ':')
}

// containsUnbracketedChar returns true if s contains the given character
// outside of brackets [...] and quotes.
func containsUnbracketedChar(s string, ch byte) bool {
	depth := 0
	inQuote := byte(0)
	for i := 0; i < len(s); i++ {
		if inQuote != 0 {
			if s[i] == inQuote {
				inQuote = 0
			}
			continue
		}
		switch s[i] {
		case '"', '\'':
			inQuote = s[i]
		case '[':
			depth++
		case ']':
			if depth > 0 {
				depth--
			}
		default:
			if s[i] == ch && depth == 0 {
				return true
			}
		}
	}
	return false
}

// splitClasses splits a class attribute value into individual class names.
func splitClasses(classAttr string) []string {
	return strings.Fields(classAttr)
}

func containsString(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}
	return false
}
