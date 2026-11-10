"use strict";
const $ = (s) => document.querySelector(s);
const fmtTime = (t) => new Date(t * 1000).toLocaleString();
const fmtSize = (n) => n < 1024 ? n + " B" : n < 1048576 ? (n / 1024).toFixed(1) + " KB" : (n / 1048576).toFixed(1) + " MB";
const short = (h) => h.slice(0, 12) + "…";

let report = null, filter = "all", query = "", baseline = null, timer = null, busy = false, workspaceCount = 0, toastTimer;

async function api(url, body) {
  const opts = body === undefined ? {} : { method: "POST", headers: { "Content-Type": "application/json", "X-FIC": "1" }, body: JSON.stringify(body) };
  const res = await fetch(url, opts);
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || res.statusText);
  return data;
}
function say(msg, isErr = false) {
  const st = $("#status");
  st.textContent = msg;
  st.classList.toggle("err", isErr);
  const t = $("#toast");  // toast is always visible, wherever the person is on the page
  t.textContent = msg;
  t.className = "toast show" + (isErr ? " err" : "");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.remove("show"), isErr ? 9000 : 4500);
}
async function run(fn, btn) {
  if (busy) return say("Still working on the previous action. Try again in a moment.");
  busy = true;
  const label = btn && btn.textContent;
  if (btn) { btn.classList.add("working"); btn.textContent = "Working…"; btn.setAttribute("aria-busy", "true"); }
  try { await fn(); }
  catch (e) {
    say(e instanceof TypeError ? "Can't reach the HASHSENTINEL server. Make sure `python server.py` is running and that you opened http://127.0.0.1:8000 in the browser." : e.message, true);
  } finally {
    busy = false;
    if (btn) { btn.classList.remove("working"); btn.textContent = label; btn.removeAttribute("aria-busy"); }
  }
}
function el(tag, props = {}, ...kids) {
  const n = Object.assign(document.createElement(tag), props);
  kids.forEach((k) => n.append(k));
  return n;
}
const patterns = () => $("#ignore").value.split(",").map((s) => s.trim()).filter(Boolean);

// ---------- baseline ----------
function showBaseline(b) {
  baseline = b;
  const info = $("#baseInfo");
  info.replaceChildren(b ? `Baseline: ${b.count} files in ${b.folder} (${b.algo.toUpperCase()}), created ${fmtTime(b.created)}.` : "No baseline yet.");
  if (b) {
    info.append(el("span", { className: "sig " + (b.verified ? "ok" : "bad"), textContent: b.verified ? "Baseline signature valid" : "Baseline was modified!" }));
    $("#folder").value = b.folder;
    $("#algo").value = b.algo;
    $("#ignore").value = (b.ignore || []).join(", ");
  }
  $("#scanBase").textContent = b ? `Comparing against the baseline of ${b.count} files in ${b.folder}, created ${fmtTime(b.created)}.` : "No baseline yet. Create one above.";
  $("#scanBtn").disabled = $("#acceptBtn").disabled = !b;
  if (!b) setAuto(0);
}

function showHistory(list) {
  const ul = $("#history");
  ul.replaceChildren();
  if (!list.length) return ul.append(el("li", { className: "muted", textContent: "No scans yet." }));
  list.forEach((h) => {
    const changes = h.added + h.modified + h.deleted + h.moved;
    const li = el("li", {},
      el("span", { className: "t", textContent: fmtTime(h.time) }),
      el("span", { textContent: changes ? `${changes} change${changes > 1 ? "s" : ""}` : "No changes" }),
      el("span", { className: "muted", textContent: `+${h.added} added · ~${h.modified} modified · −${h.deleted} deleted · ${h.moved} moved` }));
    if (h.verified === false) li.append(el("span", { className: "tamper", textContent: "Baseline tampered" }));
    ul.append(li);
  });
}

// ---------- report ----------
function flatten(r) {
  const rows = [];
  r.modified.forEach((f) => rows.push({ status: "modified", path: f.path, old: f.old, new: f.new }));
  r.added.forEach((f) => rows.push({ status: "added", path: f.path, new: f }));
  r.deleted.forEach((f) => rows.push({ status: "deleted", path: f.path, old: f }));
  r.moved.forEach((m) => rows.push({ status: "moved", path: m.to, from: m.from, hash: m.hash }));
  return rows;
}

function detail(row) {
  const wrap = el("div");
  const hash = (h) => el("span", { className: "hash", textContent: short(h) });
  if (row.status === "modified") {
    wrap.append(`Size ${fmtSize(row.old.size)} → ${fmtSize(row.new.size)}`,
      el("span", { className: "hash" }, el("span", { className: "old", textContent: short(row.old.hash) }), "  →  ", el("span", { className: "new", textContent: short(row.new.hash) })));
  } else if (row.status === "added") wrap.append(`New file, ${fmtSize(row.new.size)}`, hash(row.new.hash));
  else if (row.status === "deleted") wrap.append(`File no longer exists (was ${fmtSize(row.old.size)})`, hash(row.old.hash));
  else wrap.append(`Same content, moved from ${row.from}`, hash(row.hash));
  return wrap;
}

function renderReport() {
  const r = report, rows = flatten(r);
  $("#result").hidden = false;
  const counts = { added: r.added.length, modified: r.modified.length, deleted: r.deleted.length, moved: r.moved.length, unchanged: r.unchanged };

  const v = $("#verdict");
  const bad = rows.length > 0 || !r.baselineVerified;
  v.classList.toggle("bad", bad);
  const headline = !r.baselineVerified ? "The saved baseline file was altered outside this app. Do not trust this comparison."
    : rows.length ? `${rows.length} change${rows.length > 1 ? "s" : ""} found since the baseline.`
    : `No changes. All ${r.total} files match the baseline.`;
  v.replaceChildren(headline, el("small", { textContent: `Scanned ${r.total} files in ${r.seconds}s at ${fmtTime(r.scannedAt)}.` +
    (r.ignore.length ? ` Ignoring: ${r.ignore.join(", ")}.` : "") + (r.skipped.length ? ` ${r.skipped.length} unreadable file(s) skipped.` : "") }));

  $("#tiles").replaceChildren(...Object.entries(counts).map(([k, n]) =>
    el("div", { className: "tile " + k }, el("b", { textContent: n }), el("span", { textContent: k[0].toUpperCase() + k.slice(1) }))));

  $("#chips").replaceChildren(...["all", "modified", "added", "deleted", "moved"].map((k) => {
    const b = el("button", { className: "chip", type: "button", textContent: k === "all" ? `All (${rows.length})` : `${k[0].toUpperCase() + k.slice(1)} (${counts[k]})` });
    b.setAttribute("aria-pressed", String(filter === k));
    b.onclick = () => { filter = k; renderReport(); };
    return b;
  }));

  const shown = rows.filter((x) => (filter === "all" || x.status === filter) && x.path.toLowerCase().includes(query));
  const tbody = $("#rows");
  tbody.replaceChildren();
  if (!shown.length) tbody.append(el("tr", {}, el("td", { colSpan: 3, className: "empty", textContent: rows.length ? "No files match this filter." : "Nothing to report." })));
  shown.forEach((row) => tbody.append(el("tr", {},
    el("td", {}, el("span", { className: "badge " + row.status, textContent: row.status })),
    el("td", { className: "path", textContent: row.path }),
    el("td", {}, detail(row)))));
  $("#jsonBtn").disabled = $("#csvBtn").disabled = false;
}

async function scan(quiet) {
  if (!quiet) say("Scanning…");
  const d = await api("/api/scan", {});
  report = d.report;
  renderReport();
  showHistory(d.history);
  say(`Scan complete at ${new Date().toLocaleTimeString()}.`);
}

// ---------- workspace (add files from your computer) ----------
function showWorkspace(files) {
  workspaceCount = files.length;
  const total = files.reduce((n, f) => n + f.size, 0);
  $("#wsSummary").textContent = files.length ? `${files.length} file${files.length > 1 ? "s" : ""} in workspace (${fmtSize(total)}).` : "No files added yet.";
  $("#wsBaseline").disabled = $("#wsClear").disabled = !files.length;
  const ul = $("#wsList");
  ul.hidden = !files.length;
  ul.replaceChildren(...files.map((f) => {
    const rm = el("button", { type: "button", textContent: "Remove" });
    rm.setAttribute("aria-label", "Remove " + f.path);
    rm.onclick = () => run(async () => showWorkspace((await api("/api/workspace/delete", { path: f.path })).workspace));
    return el("li", {}, el("span", { className: "p", textContent: f.path }), el("span", { className: "s", textContent: fmtSize(f.size) }), rm);
  }));
}

async function uploadAll(items) {  // items: [{file, rel}]
  if (!items.length) return say("No files found to add.", true);
  let done = 0, replaced = 0;
  const bar = el("div", { className: "progress" }, el("i"));
  $("#wsSummary").replaceChildren(`Adding ${items.length} file${items.length > 1 ? "s" : ""}…`, bar);
  for (const { file, rel } of items) {
    const res = await fetch("/api/upload?path=" + encodeURIComponent(rel), {
      method: "POST", headers: { "Content-Type": "application/octet-stream", "X-FIC": "1" }, body: file });
    const d = await res.json();
    if (!res.ok) throw new Error(d.error || "Upload failed");
    if (d.replaced) replaced++;
    bar.firstChild.style.width = (++done / items.length * 100) + "%";
  }
  showWorkspace((await api("/api/state")).workspace);
  say(`Added ${done} file${done > 1 ? "s" : ""}` + (replaced ? ` (${replaced} replaced an existing copy)` : "") +
    (baseline && baseline.folder.endsWith("workspace") ? ". Click “Scan now” to compare with the baseline." : ". Click “Create baseline from these files”."));
}
const fromInput = (input) => [...input.files].map((file) => ({ file, rel: file.webkitRelativePath || file.name }));

async function fromDrop(dt) {  // supports dropped folders
  const entries = [...dt.items].map((i) => i.webkitGetAsEntry && i.webkitGetAsEntry()).filter(Boolean);  // read before any await
  const out = [];
  async function walk(entry, prefix) {
    if (entry.isFile) {
      out.push({ file: await new Promise((res, rej) => entry.file(res, rej)), rel: prefix + entry.name });
    } else {
      const reader = entry.createReader();
      let batch;
      do {
        batch = await new Promise((res, rej) => reader.readEntries(res, rej));
        for (const e of batch) await walk(e, prefix + entry.name + "/");
      } while (batch.length);
    }
  }
  for (const e of entries) await walk(e, "");
  return out;
}

const drop = $("#drop");
$("#pickFiles").onclick = () => $("#fileInput").click();
$("#pickFolder").onclick = () => $("#folderInput").click();
drop.onkeydown = (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); $("#fileInput").click(); } };
for (const id of ["#fileInput", "#folderInput"]) {
  $(id).onchange = (e) => { const items = fromInput(e.target); e.target.value = ""; run(() => uploadAll(items)); };
}
["dragenter", "dragover"].forEach((t) => drop.addEventListener(t, (e) => { e.preventDefault(); drop.classList.add("over"); }));
["dragleave", "drop"].forEach((t) => drop.addEventListener(t, (e) => { e.preventDefault(); drop.classList.remove("over"); }));
drop.addEventListener("drop", (e) => { const dt = e.dataTransfer; run(async () => uploadAll(await fromDrop(dt))); });
window.addEventListener("dragover", (e) => e.preventDefault());
window.addEventListener("drop", (e) => e.preventDefault());

function baselineDone(d, extra = "") {
  showBaseline(d.baseline); showHistory([]); $("#result").hidden = true;
  say(`Baseline saved: ${d.baseline.count} files fingerprinted.${extra} Next, click “Scan now”.`);
  $("#h-scan").scrollIntoView({ behavior: matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth", block: "start" });
}
$("#wsBaseline").onclick = () => run(async () => {
  say("Hashing files…");
  baselineDone(await api("/api/baseline", { workspace: true, algo: $("#algo").value, ignore: patterns() }),
    " Change a file, add it again, then scan.");
}, $("#wsBaseline"));
$("#wsClear").onclick = () => run(async () => {
  if (!confirm("Remove all files from the workspace? Your originals are not touched.")) return;
  showWorkspace((await api("/api/workspace/clear", {})).workspace);
  say("Workspace cleared.");
});

// ---------- other events ----------
$("#baseForm").addEventListener("submit", (e) => {
  e.preventDefault();
  run(async () => {
    const typed = $("#folder").value.trim(), algo = $("#algo").value, ignore = patterns();
    if (!typed && !workspaceCount) throw new Error("Type a folder path, or add files from your computer first.");
    say("Hashing files…");
    baselineDone(await api("/api/baseline", typed ? { folder: typed, algo, ignore } : { workspace: true, algo, ignore }));
  }, $("#baseBtn"));
});
$("#scanBtn").onclick = () => run(() => scan(false), $("#scanBtn"));
$("#acceptBtn").onclick = () => run(async () => {
  if (!confirm("Accept all current changes as the new baseline? Future scans compare against today's files.")) return;
  showBaseline((await api("/api/accept", {})).baseline);
  $("#result").hidden = true;
  say("Changes accepted. The current files are now the baseline.");
});
document.querySelectorAll("[data-demo]").forEach((b) => (b.onclick = () => run(async () => {
  const d = await api("/api/demo", { step: b.dataset.demo });
  if (b.dataset.demo === "reset") { $("#folder").value = d.path; say(d.message + " Now click “Create baseline”."); }
  else say(d.message + " Now click “Scan now”.");
})));
$("#resetBtn").onclick = () => run(async () => {
  if (!confirm("Delete the saved baseline and scan history? Your files are not touched.")) return;
  const d = await api("/api/reset", {});
  showBaseline(null); showHistory([]); $("#result").hidden = true;
  $("#jsonBtn").disabled = $("#csvBtn").disabled = true;
  say(d.message);
});

function setAuto(sec) {
  clearInterval(timer);
  $("#auto").value = String(sec);
  if (sec > 0) timer = setInterval(() => { if (baseline && !busy) run(() => scan(true)); }, sec * 1000);
}
$("#auto").onchange = (e) => {
  const s = +e.target.value;
  if (s && !baseline) { setAuto(0); return say("Create a baseline before turning on auto-scan.", true); }
  setAuto(s);
  say(s ? `Auto-scan every ${s} seconds.` : "Auto-scan off.");
};

$("#search").oninput = (e) => { query = e.target.value.toLowerCase(); if (report) renderReport(); };
function download(name, text, type) {
  const a = el("a", { href: URL.createObjectURL(new Blob([text], { type })), download: name });
  a.click();
  URL.revokeObjectURL(a.href);
}
const csvCell = (v) => '"' + String(v ?? "").replace(/"/g, '""') + '"';
$("#jsonBtn").onclick = () => download("integrity-report.json", JSON.stringify(report, null, 2), "application/json");
$("#csvBtn").onclick = () => {
  const lines = [["status", "path", "old_hash", "new_hash", "old_size", "new_size"].join(",")];
  flatten(report).forEach((r) => lines.push([r.status, r.path, r.old?.hash ?? r.hash, r.new?.hash ?? r.hash, r.old?.size, r.new?.size].map(csvCell).join(",")));
  download("integrity-report.csv", lines.join("\n"), "text/csv");
};

run(async () => {
  const s = await api("/api/state");
  showBaseline(s.baseline); showHistory(s.history); showWorkspace(s.workspace);
  $("#folder").placeholder = s.demoPath;
  if (s.baseline) say("Baseline loaded. Click “Scan now” to compare.");
});

// ---------- theme picker & environment checks ----------
const themeSel = $("#theme");
if (window.HS_THEME) { themeSel.value = HS_THEME.get(); themeSel.onchange = () => HS_THEME.set(themeSel.value); }
if (location.protocol === "file:") {
  const b = $("#banner");
  b.hidden = false;
  b.textContent = "This page was opened as a file, so it can't talk to the server. Run `python server.py`, then open http://127.0.0.1:8000.";
}
