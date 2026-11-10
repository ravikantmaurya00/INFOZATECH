const $ = (s) => document.querySelector(s);
const state = { tab: "caesar", mode: "encrypt" };
const NOTES = {
  caesar: "Shifts every letter by a fixed amount. Only 26 keys exist, so it is trivially broken.",
  vigenere: "Repeats a keyword to vary the shift per letter. Harder than Caesar, but still breakable by statistics.",
  aes: "AES-256 in GCM mode. Your passphrase is stretched into a key, and any tampering is detected on decrypt.",
};

function render() {
  document.querySelectorAll(".tabs button").forEach((b) => b.setAttribute("aria-selected", b.dataset.tab === state.tab));
  document.querySelectorAll("[data-for]").forEach((el) => (el.hidden = el.dataset.for !== state.tab));
  document.querySelectorAll(".seg button").forEach((b) => b.setAttribute("aria-pressed", b.dataset.mode === state.mode));
  $("#note").textContent = NOTES[state.tab];
  $("#run").textContent = state.mode === "encrypt" ? "Encrypt" : "Decrypt";
  ["#anatomy", "#brutePanel"].forEach((s) => ($(s).hidden = true));
  $("#error").hidden = true;
}

async function api(path, body) {
  const res = await fetch(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  const data = await res.json().catch(() => ({ error: "Unexpected server response." }));
  if (!res.ok) throw new Error(data.error || "Request failed.");
  return data;
}

function showError(msg) { const e = $("#error"); e.textContent = msg; e.hidden = !msg; }

async function run() {
  showError("");
  $("#brutePanel").hidden = true;
  const body = { text: $("#input").value, mode: state.mode };
  if (state.tab === "caesar") body.shift = parseInt($("#shift").value, 10) || 0;
  if (state.tab === "vigenere") body.key = $("#vkey").value;
  if (state.tab === "aes") { body.passphrase = $("#pass").value; body.kdf = $("#kdf").value; }
  $("#run").disabled = true;
  try {
    const { result } = await api(`/api/${state.tab}`, body);
    $("#output").value = result;
    if (state.tab === "aes" && state.mode === "encrypt") showAnatomy(result); else $("#anatomy").hidden = true;
  } catch (e) { $("#output").value = ""; showError(e.message); }
  finally { $("#run").disabled = false; }
}

function showAnatomy(b64) {
  const total = atob(b64).length;
  const parts = [
    ["Header (magic, KDF, cost)", 9, "--c-head"],
    ["Salt (unique per message)", 16, "--c-salt"],
    ["Nonce (unique per message)", 12, "--c-nonce"],
    ["Ciphertext", total - 37 - 16, "--c-ct"],
    ["Auth tag (detects tampering)", 16, "--c-tag"],
  ];
  const bar = $("#anatomyBar"), legend = $("#anatomyLegend");
  bar.replaceChildren(); legend.replaceChildren();
  for (const [name, n, color] of parts) {
    const seg = document.createElement("span");
    seg.style.cssText = `flex:${n};background:var(${color})`;
    seg.title = `${name}: ${n} bytes`;
    bar.append(seg);
    const li = document.createElement("li");
    li.style.setProperty("--c", `var(${color})`);
    li.textContent = `${name}: ${n} bytes`;
    legend.append(li);
  }
  $("#anatomy").hidden = false;
}

async function brute() {
  showError("");
  try {
    const { result } = await api("/api/caesar/bruteforce", { text: $("#input").value });
    const list = $("#bruteList");
    list.replaceChildren();
    result.forEach(({ shift, text }) => {
      const li = document.createElement("li");
      li.value = shift;
      li.textContent = `shift ${shift}: ${text}`;
      list.append(li);
    });
    $("#brutePanel").hidden = false;
  } catch (e) { showError(e.message); }
}

function strength(pw) {
  if (!pw) return { bits: 0, label: "Enter a passphrase" };
  const pool = (/[a-z]/.test(pw) ? 26 : 0) + (/[A-Z]/.test(pw) ? 26 : 0) + (/\d/.test(pw) ? 10 : 0) + (/[^A-Za-z0-9]/.test(pw) ? 33 : 0);
  const bits = Math.round(pw.length * Math.log2(pool || 1));
  const label = bits < 40 ? "Weak" : bits < 60 ? "Fair" : bits < 80 ? "Good" : "Strong";
  return { bits, label: `${label} (about ${bits} bits; a longer phrase beats a complex short one)` };
}

document.querySelectorAll(".tabs button").forEach((b) => b.addEventListener("click", () => { state.tab = b.dataset.tab; render(); }));
document.querySelectorAll(".seg button").forEach((b) => b.addEventListener("click", () => { state.mode = b.dataset.mode; render(); }));
$("#run").addEventListener("click", run);
$("#brute").addEventListener("click", brute);
$("#swap").addEventListener("click", () => { $("#input").value = $("#output").value; $("#output").value = ""; });
$("#copy").addEventListener("click", async () => {
  try { await navigator.clipboard.writeText($("#output").value); $("#copy").textContent = "Copied"; }
  catch { $("#output").select(); $("#copy").textContent = "Press Ctrl+C to copy"; }
  setTimeout(() => ($("#copy").textContent = "Copy output"), 1500);
});
$("#pass").addEventListener("input", (e) => {
  const { bits, label } = strength(e.target.value);
  const bar = $("#meterBar");
  bar.style.width = Math.min(100, (bits / 100) * 100) + "%";
  bar.style.background = bits < 40 ? "var(--err)" : bits < 80 ? "var(--c-salt)" : "var(--c-nonce)";
  $("#meterText").textContent = label;
});
render();
