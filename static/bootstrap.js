(function() {
  // __UBLPROXY_PORTAL__ and __UBLPROXY_TOKEN__ are replaced server-side.
  // __UBLPROXY_HOST__ is the actual hostname of the page being proxied.
  var P = "__UBLPROXY_PORTAL__";
  var T = "__UBLPROXY_TOKEN__";
  var H = "__UBLPROXY_HOST__";
  var loaded = false;

  document.addEventListener("keydown", function(e) {
    // Alt+Shift+B to toggle the element picker
    if (!e.altKey || !e.shiftKey || e.code !== "KeyB") return;
    e.preventDefault();
    e.stopPropagation();

    if (loaded) {
      // Toggle visibility if already loaded
      var existing = document.getElementById("__ublproxy_picker__");
      if (existing) {
        if (existing.style.display === "none") {
          existing.style.display = "";
          if (existing.__ublproxyOpen) existing.__ublproxyOpen();
        } else {
          existing.style.display = "none";
        }
      }
      return;
    }

    loaded = true;

    // Fetch the picker script from the portal and inject it
    fetch(P + "/api/picker.js", {
      headers: { "Authorization": "Bearer " + T }
    })
    .then(function(r) {
      if (!r.ok) throw new Error("Failed to load picker: " + r.status);
      return r.text();
    })
    .then(function(code) {
      // Execute the picker code with portal URL, token, and host in scope
      var fn = new Function("UBLPROXY_PORTAL", "UBLPROXY_TOKEN", "UBLPROXY_HOST", code);
      fn(P, T, H);
    })
    .catch(function(err) {
      console.error("[ublproxy]", err);
      loaded = false;
    });
  });
})();
