package blocklist

import "strings"

// ScriptletSource returns the JavaScript source for a scriptlet by name,
// with the given arguments substituted. Returns empty string if unknown.
func ScriptletSource(name string, args []string) string {
	// Normalize aliases
	canonical, ok := scriptletAliases[name]
	if ok {
		name = canonical
	}

	tmpl, ok := scriptletLibrary[name]
	if !ok {
		return ""
	}

	return tmpl(args)
}

// scriptletAliases maps short names to canonical scriptlet names.
var scriptletAliases = map[string]string{
	"set":  "set-constant",
	"aopr": "abort-on-property-read",
	"aopw": "abort-on-property-write",
	"acis": "abort-current-inline-script",
	"aeld": "addEventListener-defuser",
	"ra":   "remove-attr",
	"rc":   "remove-class",
}

// scriptletLibrary maps scriptlet names to template functions that generate
// executable JavaScript. Each function takes the arguments from the filter
// rule and returns a self-contained IIFE.
var scriptletLibrary = map[string]func([]string) string{
	"set-constant": func(args []string) string {
		if len(args) < 2 {
			return ""
		}
		prop := jsStringEscape(args[0])
		value := args[1]
		jsValue := resolveConstantValue(value)
		return `(function() {
	var prop = '` + prop + `';
	var value = ` + jsValue + `;
	var chain = prop.split('.');
	var owner = window;
	for (var i = 0; i < chain.length - 1; i++) {
		if (!(chain[i] in owner)) { owner[chain[i]] = {}; }
		owner = owner[chain[i]];
	}
	var key = chain[chain.length - 1];
	try {
		Object.defineProperty(owner, key, {
			configurable: false,
			get: function() { return value; },
			set: function() {}
		});
	} catch(e) { owner[key] = value; }
})();
`
	},

	"abort-on-property-read": func(args []string) string {
		if len(args) < 1 {
			return ""
		}
		prop := jsStringEscape(args[0])
		return `(function() {
	var prop = '` + prop + `';
	var chain = prop.split('.');
	var owner = window;
	for (var i = 0; i < chain.length - 1; i++) {
		if (!(chain[i] in owner)) { owner[chain[i]] = {}; }
		owner = owner[chain[i]];
	}
	var key = chain[chain.length - 1];
	Object.defineProperty(owner, key, {
		configurable: true,
		get: function() { throw new ReferenceError(prop); },
		set: function() {}
	});
})();
`
	},

	"abort-on-property-write": func(args []string) string {
		if len(args) < 1 {
			return ""
		}
		prop := jsStringEscape(args[0])
		return `(function() {
	var prop = '` + prop + `';
	var chain = prop.split('.');
	var owner = window;
	for (var i = 0; i < chain.length - 1; i++) {
		if (!(chain[i] in owner)) { owner[chain[i]] = {}; }
		owner = owner[chain[i]];
	}
	var key = chain[chain.length - 1];
	var existing = owner[key];
	Object.defineProperty(owner, key, {
		configurable: true,
		get: function() { return existing; },
		set: function() { throw new ReferenceError(prop); }
	});
})();
`
	},

	"abort-current-inline-script": func(args []string) string {
		if len(args) < 1 {
			return ""
		}
		prop := jsStringEscape(args[0])
		needle := ""
		if len(args) >= 2 {
			needle = jsStringEscape(args[1])
		}
		return `(function() {
	var prop = '` + prop + `';
	var needle = '` + needle + `';
	var chain = prop.split('.');
	var owner = window;
	for (var i = 0; i < chain.length - 1; i++) {
		if (!(chain[i] in owner)) { return; }
		owner = owner[chain[i]];
	}
	var key = chain[chain.length - 1];
	var existing = owner[key];
	Object.defineProperty(owner, key, {
		configurable: true,
		get: function() {
			if (needle === '' || (document.currentScript && document.currentScript.textContent.indexOf(needle) !== -1)) {
				throw new ReferenceError(prop);
			}
			return existing;
		},
		set: function(v) { existing = v; }
	});
})();
`
	},

	"addEventListener-defuser": func(args []string) string {
		typeNeedle := ""
		handlerNeedle := ""
		if len(args) >= 1 {
			typeNeedle = jsStringEscape(args[0])
		}
		if len(args) >= 2 {
			handlerNeedle = jsStringEscape(args[1])
		}
		return `(function() {
	var typeNeedle = '` + typeNeedle + `';
	var handlerNeedle = '` + handlerNeedle + `';
	var orig = EventTarget.prototype.addEventListener;
	EventTarget.prototype.addEventListener = function(type, handler, options) {
		if (typeNeedle !== '' && type.indexOf(typeNeedle) === -1) {
			return orig.call(this, type, handler, options);
		}
		if (handlerNeedle !== '' && (typeof handler === 'function') && handler.toString().indexOf(handlerNeedle) === -1) {
			return orig.call(this, type, handler, options);
		}
	};
})();
`
	},

	"nowebrtc": func(args []string) string {
		return `(function() {
	if (typeof window.RTCPeerConnection === 'function') {
		window.RTCPeerConnection = function() { throw new DOMException('blocked by ublproxy'); };
	}
	if (typeof window.webkitRTCPeerConnection === 'function') {
		window.webkitRTCPeerConnection = function() { throw new DOMException('blocked by ublproxy'); };
	}
})();
`
	},

	"no-setTimeout-if": func(args []string) string {
		needle := ""
		delay := ""
		if len(args) >= 1 {
			needle = jsStringEscape(args[0])
		}
		if len(args) >= 2 {
			delay = jsStringEscape(args[1])
		}
		return `(function() {
	var needle = '` + needle + `';
	var delay = '` + delay + `';
	var orig = window.setTimeout;
	window.setTimeout = function(fn, ms) {
		var s = typeof fn === 'function' ? fn.toString() : String(fn);
		if (needle !== '' && s.indexOf(needle) !== -1) {
			if (delay === '' || String(ms) === delay) { return; }
		}
		return orig.apply(this, arguments);
	};
})();
`
	},

	"no-setInterval-if": func(args []string) string {
		needle := ""
		delay := ""
		if len(args) >= 1 {
			needle = jsStringEscape(args[0])
		}
		if len(args) >= 2 {
			delay = jsStringEscape(args[1])
		}
		return `(function() {
	var needle = '` + needle + `';
	var delay = '` + delay + `';
	var orig = window.setInterval;
	window.setInterval = function(fn, ms) {
		var s = typeof fn === 'function' ? fn.toString() : String(fn);
		if (needle !== '' && s.indexOf(needle) !== -1) {
			if (delay === '' || String(ms) === delay) { return; }
		}
		return orig.apply(this, arguments);
	};
})();
`
	},

	"prevent-fetch": func(args []string) string {
		needle := ""
		if len(args) >= 1 {
			needle = jsStringEscape(args[0])
		}
		return `(function() {
	var needle = '` + needle + `';
	var origFetch = window.fetch;
	window.fetch = function(resource, init) {
		var url = typeof resource === 'string' ? resource : (resource && resource.url ? resource.url : '');
		if (needle === '' || url.indexOf(needle) !== -1) {
			return Promise.resolve(new Response('', {status: 200, statusText: 'OK'}));
		}
		return origFetch.apply(this, arguments);
	};
})();
`
	},

	"json-prune": func(args []string) string {
		propsToRemove := ""
		if len(args) >= 1 {
			propsToRemove = jsStringEscape(args[0])
		}
		return `(function() {
	var props = '` + propsToRemove + `'.split(' ');
	var origParse = JSON.parse;
	JSON.parse = function() {
		var obj = origParse.apply(this, arguments);
		if (obj && typeof obj === 'object') {
			for (var i = 0; i < props.length; i++) {
				var path = props[i].split('.');
				var target = obj;
				for (var j = 0; j < path.length - 1; j++) {
					if (path[j] === '*') {
						// wildcard: apply to all keys at this level
						if (typeof target === 'object' && target !== null) {
							var keys = Object.keys(target);
							for (var k = 0; k < keys.length; k++) {
								if (typeof target[keys[k]] === 'object') {
									delete target[keys[k]][path[path.length-1]];
								}
							}
						}
						target = null;
						break;
					}
					if (!target || typeof target !== 'object') { target = null; break; }
					target = target[path[j]];
				}
				if (target && typeof target === 'object') {
					delete target[path[path.length - 1]];
				}
			}
		}
		return obj;
	};
})();
`
	},

	"remove-attr": func(args []string) string {
		if len(args) < 1 {
			return ""
		}
		attr := jsStringEscape(args[0])
		selector := ""
		if len(args) >= 2 {
			selector = jsStringEscape(args[1])
		}
		return `(function() {
	var attr = '` + attr + `';
	var selector = '` + selector + `' || '[' + attr + ']';
	var remove = function() {
		var els = document.querySelectorAll(selector);
		for (var i = 0; i < els.length; i++) { els[i].removeAttribute(attr); }
	};
	if (document.readyState === 'loading') {
		document.addEventListener('DOMContentLoaded', remove);
	} else {
		remove();
	}
	var observer = new MutationObserver(remove);
	observer.observe(document.documentElement, {childList: true, subtree: true, attributes: true});
})();
`
	},
}

// resolveConstantValue maps uBO constant names to JavaScript expressions.
func resolveConstantValue(val string) string {
	switch val {
	case "true":
		return "true"
	case "false":
		return "false"
	case "undefined":
		return "undefined"
	case "null":
		return "null"
	case "noopFunc":
		return "(function(){})"
	case "trueFunc":
		return "(function(){return true})"
	case "falseFunc":
		return "(function(){return false})"
	case "''", `""`:
		return "''"
	case "0":
		return "0"
	case "1":
		return "1"
	case "-1":
		return "-1"
	case "[]":
		return "[]"
	case "{}":
		return "{}"
	case "NaN":
		return "NaN"
	default:
		return "'" + jsStringEscape(val) + "'"
	}
}

// jsStringEscape escapes a string for safe inclusion in a JS single-quoted string.
func jsStringEscape(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `'`, `\'`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	s = strings.ReplaceAll(s, "\r", `\r`)
	s = strings.ReplaceAll(s, "</script", `<\/script`)
	return s
}
