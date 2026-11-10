/* HASHSENTINEL theme manager: System / Light / Dark / Midnight. Loaded in <head> to avoid a flash. */
(function () {
  "use strict";
  var KEY = "hashsentinel-theme", mq = window.matchMedia("(prefers-color-scheme: dark)");
  function pref() { try { return localStorage.getItem(KEY) || "system"; } catch (e) { return "system"; } }
  function apply(p) {
    document.documentElement.dataset.theme = p === "system" ? (mq.matches ? "dark" : "light") : p;
  }
  window.HS_THEME = {
    get: pref,
    set: function (p) { try { localStorage.setItem(KEY, p); } catch (e) {} apply(p); }
  };
  if (mq.addEventListener) mq.addEventListener("change", function () { if (pref() === "system") apply("system"); });
  apply(pref());
})();
