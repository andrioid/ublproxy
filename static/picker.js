// Element picker for ublproxy
// Loaded by the bootstrap script when the user presses Alt+Shift+B.
// Receives UBLPROXY_PORTAL, UBLPROXY_TOKEN, and UBLPROXY_HOST as function arguments.

// --- Selector Generation ---

function generateSelector(el) {
  if (el.id) return "#" + CSS.escape(el.id);

  var tag = el.tagName.toLowerCase();

  // Try classes first - most specific and common for ad elements
  if (el.classList.length > 0) {
    var classSelector = "." + Array.from(el.classList).map(CSS.escape).join(".");
    // Check uniqueness on page
    if (document.querySelectorAll(classSelector).length === 1) return classSelector;
    // With tag
    var tagClass = tag + classSelector;
    if (document.querySelectorAll(tagClass).length === 1) return tagClass;
    // Return class selector even if not unique (still useful as element hiding)
    return classSelector;
  }

  // Try common identifying attributes
  var attrs = ["name", "data-ad", "data-ad-slot", "data-testid", "role"];
  for (var i = 0; i < attrs.length; i++) {
    var val = el.getAttribute(attrs[i]);
    if (val) {
      var attrSel = tag + "[" + attrs[i] + '="' + CSS.escape(val) + '"]';
      if (document.querySelectorAll(attrSel).length <= 3) return attrSel;
    }
  }

  // Fallback: tag with nth-of-type (nth-child counts all siblings
  // regardless of tag, nth-of-type counts only same-tag siblings)
  var parent = el.parentElement;
  if (parent) {
    var siblings = Array.from(parent.children).filter(function(c) {
      return c.tagName === el.tagName;
    });
    if (siblings.length === 1) {
      return generateSelector(parent) + " > " + tag;
    }
    var idx = siblings.indexOf(el) + 1;
    return generateSelector(parent) + " > " + tag + ":nth-of-type(" + idx + ")";
  }

  return tag;
}

// --- Panel UI (Shadow DOM for full isolation) ---

var panelHost = document.createElement("div");
panelHost.id = "__ublproxy_picker__";
panelHost.style.cssText = "position:fixed;top:16px;right:16px;z-index:2147483647;";
document.body.appendChild(panelHost);

var shadow = panelHost.attachShadow({ mode: "closed" });

shadow.innerHTML = '<style>'
  + '*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }'
  + ':host { font: 14px/1.5 system-ui, -apple-system, sans-serif; }'
  + '.panel { background: #1a1a2e; color: #e0e0e0; border-radius: 10px;'
  + '  box-shadow: 0 8px 32px rgba(0,0,0,0.4); padding: 16px; min-width: 320px; max-width: 420px;'
  + '  cursor: move; user-select: none; }'
  + '.title { font-size: 13px; font-weight: 600; color: #888; text-transform: uppercase;'
  + '  letter-spacing: 0.05em; margin-bottom: 12px; display: flex; justify-content: space-between; align-items: center; }'
  + '.selector { font: 13px/1.4 "SF Mono", Monaco, Menlo, monospace; background: #0d0d1a;'
  + '  padding: 10px 12px; border-radius: 6px; color: #7dd3fc; word-break: break-all;'
  + '  margin-bottom: 12px; min-height: 38px; }'
  + '.domain { font-size: 12px; color: #666; margin-bottom: 12px; }'
  + '.buttons { display: flex; gap: 8px; }'
  + 'button { flex: 1; padding: 8px 16px; border: none; border-radius: 6px; font: inherit;'
  + '  font-weight: 500; cursor: pointer; transition: background 0.15s; }'
  + '.block-btn { background: #dc2626; color: #fff; }'
  + '.block-btn:hover { background: #ef4444; }'
  + '.cancel-btn { background: #333; color: #ccc; }'
  + '.cancel-btn:hover { background: #444; }'
  + '.close-btn { background: none; border: none; color: #666; cursor: pointer;'
  + '  font-size: 18px; line-height: 1; padding: 0 4px; }'
  + '.close-btn:hover { color: #aaa; }'
  + '.status { font-size: 12px; color: #4ade80; margin-top: 8px; text-align: center; display: none; }'
  + '.status.error { color: #f87171; }'
  + '.hint { font-size: 12px; color: #666; text-align: center; margin-bottom: 8px; }'
  + '.highlight { position: fixed; pointer-events: none; border: 2px solid #ff4444;'
  + '  background: rgba(255,68,68,0.15); transition: all 0.05s ease-out; display: none; }'
  + '@media (prefers-reduced-motion: reduce) { * { transition: none !important; } }'
  + '</style>'
  + '<div class="highlight" id="highlight"></div>'
  + '<div class="panel" id="panel">'
  + '  <div class="title"><span>ublproxy picker</span><button class="close-btn" id="close" aria-label="Close">&times;</button></div>'
  + '  <div class="hint" id="hint">Hover over an element and click to select it</div>'
  + '  <div class="selector" id="selector" style="display:none"></div>'
  + '  <div class="domain" id="domain" style="display:none"></div>'
  + '  <div class="buttons" id="buttons" style="display:none">'
  + '    <button class="block-btn" id="block">Block element</button>'
  + '    <button class="cancel-btn" id="cancel">Cancel</button>'
  + '  </div>'
  + '  <div class="status" id="status"></div>'
  + '</div>';

var highlight = shadow.getElementById("highlight");
var panel = shadow.getElementById("panel");
var selectorEl = shadow.getElementById("selector");
var domainEl = shadow.getElementById("domain");
var hintEl = shadow.getElementById("hint");
var buttonsEl = shadow.getElementById("buttons");
var blockBtn = shadow.getElementById("block");
var cancelBtn = shadow.getElementById("cancel");
var closeBtn = shadow.getElementById("close");
var statusEl = shadow.getElementById("status");

// --- Highlight Overlay ---

var currentTarget = null;

function updateHighlight(el) {
  if (!el || el === document.body || el === document.documentElement) {
    highlight.style.display = "none";
    currentTarget = null;
    return;
  }
  var rect = el.getBoundingClientRect();
  highlight.style.display = "block";
  highlight.style.top = rect.top + "px";
  highlight.style.left = rect.left + "px";
  highlight.style.width = rect.width + "px";
  highlight.style.height = rect.height + "px";
  currentTarget = el;
}

// --- Make panel draggable ---

var dragging = false, dragX = 0, dragY = 0;

function onDragMove(e) {
  if (!dragging) return;
  panelHost.style.left = (e.clientX - dragX) + "px";
  panelHost.style.right = "auto";
  panelHost.style.top = (e.clientY - dragY) + "px";
}

function onDragUp() { dragging = false; }

panel.addEventListener("mousedown", function(e) {
  if (e.target.tagName === "BUTTON") return;
  dragging = true;
  dragX = e.clientX - panelHost.getBoundingClientRect().left;
  dragY = e.clientY - panelHost.getBoundingClientRect().top;
  e.preventDefault();
});
document.addEventListener("mousemove", onDragMove);
document.addEventListener("mouseup", onDragUp);

// --- State ---

var picking = true;
var selectedElement = null;
var selectedSelector = "";

// The actual hostname of the page being viewed, passed from the bootstrap
// script. Falls back to location.hostname if not provided.
var pageHost = (typeof UBLPROXY_HOST !== "undefined" && UBLPROXY_HOST) ? UBLPROXY_HOST : location.hostname;

// --- Event handlers ---

function isPickerElement(el) {
  while (el) {
    if (el === panelHost) return true;
    el = el.parentElement;
  }
  return false;
}

function onMouseMove(e) {
  if (!picking || dragging) return;
  var el = document.elementFromPoint(e.clientX, e.clientY);
  if (isPickerElement(el)) {
    highlight.style.display = "none";
    return;
  }
  updateHighlight(el);
}

function onMouseDown(e) {
  if (!picking) return;
  if (isPickerElement(e.target)) return;

  e.preventDefault();
  e.stopPropagation();
  e.stopImmediatePropagation();

  if (!currentTarget) return;

  selectedElement = currentTarget;
  selectedSelector = generateSelector(selectedElement);
  picking = false;

  // Update panel UI
  hintEl.style.display = "none";
  selectorEl.textContent = selectedSelector;
  selectorEl.style.display = "block";
  domainEl.textContent = pageHost;
  domainEl.style.display = "block";
  buttonsEl.style.display = "flex";
  statusEl.style.display = "none";
}

// Prevent click and mouseup from reaching the page while picking.
// mousedown alone isn't enough — browsers fire click after mouseup,
// which triggers link navigation on ad anchors.
function onClickCapture(e) {
  if (!picking && !selectedElement) return;
  if (isPickerElement(e.target)) return;
  e.preventDefault();
  e.stopPropagation();
  e.stopImmediatePropagation();
}

function onMouseUp(e) {
  if (!picking && !selectedElement) return;
  if (isPickerElement(e.target)) return;
  e.preventDefault();
  e.stopPropagation();
  e.stopImmediatePropagation();
}

function resetPicker() {
  picking = true;
  selectedElement = null;
  selectedSelector = "";
  highlight.style.display = "none";
  hintEl.style.display = "block";
  selectorEl.style.display = "none";
  domainEl.style.display = "none";
  buttonsEl.style.display = "none";
  statusEl.style.display = "none";
}

function closePicker() {
  picking = false;
  highlight.style.display = "none";
  panelHost.style.display = "none";

  // Remove all event listeners to allow clean re-open
  document.removeEventListener("mousemove", onMouseMove, true);
  document.removeEventListener("mousedown", onMouseDown, true);
  document.removeEventListener("click", onClickCapture, true);
  document.removeEventListener("mouseup", onMouseUp, true);
  document.removeEventListener("keydown", onKeyDown, true);
  document.removeEventListener("mousemove", onDragMove);
  document.removeEventListener("mouseup", onDragUp);
}

function openPicker() {
  panelHost.style.display = "";
  picking = true;
  resetPicker();

  // Re-register all event listeners
  document.addEventListener("mousemove", onMouseMove, true);
  document.addEventListener("mousedown", onMouseDown, true);
  document.addEventListener("click", onClickCapture, true);
  document.addEventListener("mouseup", onMouseUp, true);
  document.addEventListener("keydown", onKeyDown, true);
  document.addEventListener("mousemove", onDragMove);
  document.addEventListener("mouseup", onDragUp);
}

// Expose openPicker for the bootstrap script to call on re-toggle
panelHost.__ublproxyOpen = openPicker;

function onKeyDown(e) {
  if (e.key === "Escape") {
    if (selectedElement) {
      resetPicker();
    } else {
      closePicker();
    }
    e.preventDefault();
    e.stopPropagation();
  }
}

function showStatus(msg, isError) {
  statusEl.textContent = msg;
  statusEl.className = "status" + (isError ? " error" : "");
  statusEl.style.display = "block";
}

// --- Block action ---

blockBtn.addEventListener("click", function() {
  if (!selectedSelector) return;

  var rule = pageHost + "##" + selectedSelector;
  blockBtn.disabled = true;
  blockBtn.textContent = "Saving...";

  fetch(UBLPROXY_PORTAL + "/api/rules", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": "Bearer " + UBLPROXY_TOKEN
    },
    body: JSON.stringify({
      rule: rule,
      domain: pageHost
    })
  })
  .then(function(r) {
    if (!r.ok) throw new Error("HTTP " + r.status);
    return r.json();
  })
  .then(function() {
    // Immediately hide the element on the current page
    if (selectedElement) {
      selectedElement.style.setProperty("display", "none", "important");
    }
    // Also inject a style rule for immediate effect on dynamic content
    var style = document.createElement("style");
    style.textContent = selectedSelector + " { display: none !important; }";
    document.head.appendChild(style);

    showStatus("Blocked! Rule will apply on next page load.", false);
    highlight.style.display = "none";
    blockBtn.textContent = "Block element";
    blockBtn.disabled = false;
    buttonsEl.style.display = "none";

    // Reset after a short delay
    setTimeout(resetPicker, 2000);
  })
  .catch(function(err) {
    showStatus("Failed to save: " + err.message, true);
    blockBtn.textContent = "Block element";
    blockBtn.disabled = false;
  });
});

cancelBtn.addEventListener("click", resetPicker);
closeBtn.addEventListener("click", closePicker);

// --- Start picking ---

document.addEventListener("mousemove", onMouseMove, true);
document.addEventListener("mousedown", onMouseDown, true);
document.addEventListener("click", onClickCapture, true);
document.addEventListener("mouseup", onMouseUp, true);
document.addEventListener("keydown", onKeyDown, true);
