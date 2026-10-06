// Uses $, esc, fmtDate from app.js

const CP_KEY = "vt_checkpoint";
let auditRows = [];

function getCp() {
  try {
    return JSON.parse(localStorage.getItem(CP_KEY));
  } catch (e) {
    return null;
  }
}

function renderCp() {
  const cp = getCp();
  $("auCp").textContent = cp
    ? `Pinned checkpoint: entry #${cp.id}, fingerprint ${cp.hash.slice(0, 16)}…`
    : "No checkpoint pinned yet. Pin one to also catch deleted or fully rewritten history.";
}

function banner(good, html) {
  $("auBanner").className = "banner " + (good ? "good" : "bad");
  $("auBanner").innerHTML = html;
}

async function loadAudit() {
  const rows = await api("/audit?limit=200");
  if (!rows) return;

  auditRows = rows;

  const sel = $("auFilter");
  const keep = sel.value;

  const actions = [...new Set(rows.map(r => r.action))].sort();

  sel.innerHTML = '<option value="">All actions</option>' +
    actions.map(a =>
      `<option ${a === keep ? "selected" : ""}>${esc(a)}</option>`
    ).join("");

  renderAudit();
}

function renderAudit() {
  const f = $("auFilter").value;
  const rows = auditRows.filter(r => !f || r.action === f);

  $("auditRows").innerHTML = rows.length
    ? rows.map(r => `
      <tr>
        <td>${r.id}</td>
        <td>${fmtDate(r.ts)}</td>
        <td>${esc(r.actor)}</td>
        <td><span class="pill">${esc(r.action)}</span></td>
        <td>${esc(r.target)}</td>
        <td class="det">${esc(r.details)}</td>
        <td class="mono">${esc(r.hash_short)}</td>
      </tr>`
    ).join("")
    : `<tr><td colspan="7" class="muted">Nothing logged yet.</td></tr>`;
}

$("auFilter").onchange = renderAudit;
$("auRefresh").onclick = loadAudit;

$("auVerify").onclick = async () => {
  const cp = getCp();
  const qs = cp
    ? `?cp_id=${cp.id}&cp_hash=${encodeURIComponent(cp.hash)}`
    : "";

  try {
    const r = await api("/audit/verify" + qs);

    if (r.ok) {
      banner(
        true,
        `✅ <b>Integrity verified.</b> ${r.entries} entries, chain unbroken.` +
        (r.checkpoint === "ok"
          ? ` Your pinned checkpoint (#${cp.id}) still matches.`
          : "")
      );
    } else if (r.reason === "chain_broken") {
      banner(
        false,
        `🚨 <b>TAMPERING DETECTED.</b> Entry #${r.broken_at} does not match its fingerprint
        (it, or the entry before it, was edited or deleted).`
      );
    } else if (r.reason === "checkpoint_missing") {
      banner(
        false,
        `🚨 <b>HISTORY TRUNCATED.</b> The entry you pinned (#${cp.id}) no longer exists.`
      );
    } else {
      banner(
        false,
        `🚨 <b>HISTORY REWRITTEN.</b> Entry #${cp.id} no longer matches the checkpoint you pinned,
        even though the chain looks internally consistent.`
      );
    }

    loadAudit();
  } catch (e) {
    banner(false, e.message);
  }
};

$("auPin").onclick = async () => {
  try {
    const r = await api("/audit/verify");

    // Never pin a log that is already broken.
    if (!r.ok) {
      return banner(
        false,
        "🚨 Cannot pin: the log already fails verification."
      );
    }

    localStorage.setItem(
      CP_KEY,
      JSON.stringify({
        id: r.head_id,
        hash: r.head
      })
    );

    renderCp();

    banner(
      true,
      `📌 Checkpoint pinned at entry #${r.head_id}. Entries up to here are now protected against rewriting.`
    );
  } catch (e) {
    banner(false, e.message);
  }
};

renderCp();
loadAudit();
setInterval(loadAudit, 10000);