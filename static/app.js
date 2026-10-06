const $ = id => document.getElementById(id);

// Escape text before putting it in HTML, so a malicious filename can't run scripts (XSS)
const esc = s => String(s).replace(/[&<>"']/g, c =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])
);

function fmtSize(n) {
  if (n < 1024) return n + " B";
  if (n < 1048576) return (n / 1024).toFixed(1) + " KB";
  return (n / 1048576).toFixed(1) + " MB";
}

const fmtDate = s => (s ? new Date(s).toLocaleString() : "");

function say(id, text, ok) {
  $(id).className = "msg " + (ok ? "ok" : "err");
  $(id).textContent = text;
}

let buckets = [];
let currentBucket = null;
let currentObject = null;


// ---------- top bar ----------

api("/me").then(d => $("who").textContent = d.email);

$("logout").onclick = () => {
  localStorage.removeItem("token");
  location.href = "/index.html";
};


// ---------- buckets ----------

async function loadBuckets() {
  buckets = await api("/buckets");

  if (currentBucket)
    currentBucket =
      buckets.find(b => b.id === currentBucket.id) || null;

  $("buckets").innerHTML = buckets.length
    ? buckets.map(b => `
      <tr
        class="clickable ${currentBucket && currentBucket.id === b.id ? "sel" : ""}"
        onclick="selectBucket(${b.id})"
      >
        <td>${esc(b.name)}</td>
        <td>${b.object_count}</td>
        <td>${b.versioning ? "On" : "Off"}</td>
        <td>${b.lifecycle_days ? b.lifecycle_days + " days" : "—"}</td>
      </tr>
    `).join("")
    : `<tr>
         <td colspan="4" class="muted">
           No buckets yet. Create one above.
         </td>
       </tr>`;
}


$("bCreate").onclick = async () => {
  const days = $("bDays").value;

  try {
    await api("/buckets", {
      method: "POST",
      body: JSON.stringify({
        name: $("bName").value,
        versioning: $("bVer").checked,
        lifecycle_days: days ? Number(days) : null
      })
    });

    say("bMsg", "Bucket created.", true);

    $("bName").value = "";
    $("bDays").value = "";

    await loadBuckets();

  } catch (e) {
    say("bMsg", e.message, false);
  }
};


function selectBucket(id) {
  currentBucket = buckets.find(b => b.id === id);

  $("curBucket").textContent = currentBucket.name;

  $("sVer").checked = !!currentBucket.versioning;
  $("sDays").value = currentBucket.lifecycle_days || "";

  $("filesCard").classList.remove("hidden");

  $("fMsg").textContent = "";
  $("sMsg").textContent = "";

  closeHistory();

  loadBuckets();
  loadFiles();
}


// ---------- bucket settings ----------

$("sSave").onclick = async () => {
  const d = $("sDays").value;

  try {
    await api(
      `/buckets/${currentBucket.id}/settings`,
      {
        method: "PUT",
        body: JSON.stringify({
          versioning: $("sVer").checked,
          lifecycle_days: d ? Number(d) : null
        })
      }
    );

    say("sMsg", "Settings saved.", true);

    await loadBuckets();

  } catch (e) {
    say("sMsg", e.message, false);
  }
};


// ---------- files ----------

async function loadFiles() {
  if (!currentBucket) return;

  const files =
    await api(`/buckets/${currentBucket.id}/objects`);

  $("files").innerHTML = files.length
    ? files.map(f => `
      <tr>

        <td>${esc(f.obj_key)}</td>

        <td>
          <span class="pill">
            v${f.latest_version}
          </span>
        </td>

        <td>${f.version_count}</td>

        <td>${fmtSize(f.size_bytes)}</td>

        <td>${fmtDate(f.uploaded_at)}</td>

        <td class="row">

          <button
            data-act="hist"
            data-oid="${f.id}"
            data-name="${esc(f.obj_key)}"
          >
            History
          </button>

          <button
            data-act="share"
            data-vid="${f.latest_version_id}"
            data-label="${esc(currentBucket.name)}/${esc(f.obj_key)}@v${f.latest_version}"
          >
            Share
          </button>

          <button
            data-act="dl"
            data-vid="${f.latest_version_id}"
            data-name="${esc(f.obj_key)}"
          >
            Download
          </button>

          <button
            class="danger"
            data-act="del"
            data-oid="${f.id}"
            data-name="${esc(f.obj_key)}"
          >
            Delete
          </button>

        </td>

      </tr>
    `).join("")
    : `<tr>
         <td colspan="6" class="muted">
           No files yet. Upload one above.
         </td>
       </tr>`;
}


// One click handler for all buttons in the table
$("files").onclick = e => {

  const b = e.target.closest("button");

  if (!b) return;

  if (b.dataset.act === "hist")
    openHistory(
      Number(b.dataset.oid),
      b.dataset.name
    );

  if (b.dataset.act === "dl")
    downloadVersion(
      b.dataset.vid,
      b.dataset.name
    );

  if (b.dataset.act === "del")
    deleteObject(
      b.dataset.oid,
      b.dataset.name
    );
};


$("upBtn").onclick = async () => {

  const input = $("fileInput");

  if (!currentBucket || !input.files.length)
    return say(
      "fMsg",
      "Choose at least one file.",
      false
    );

  for (const file of input.files) {

    const fd = new FormData();

    fd.append("file", file);

    try {

      const r = await api(
        `/buckets/${currentBucket.id}/objects`,
        {
          method: "POST",
          body: fd
        }
      );

      say(
        "fMsg",
        `Uploaded ${r.key} as version ${r.version}`,
        true
      );

    } catch (e) {

      say(
        "fMsg",
        `${file.name}: ${e.message}`,
        false
      );

    }
  }

  input.value = "";

  await loadFiles();
  await loadBuckets();

  if (currentObject)
    loadVersions();
};


async function downloadVersion(vid, name) {

  const res = await fetch(
    `/api/versions/${vid}/download`,
    {
      headers: {
        Authorization:
          "Bearer " + localStorage.getItem("token")
      }
    }
  );

  if (!res.ok)
    return alert("Download failed");

  const url =
    URL.createObjectURL(await res.blob());

  const a = document.createElement("a");

  a.href = url;
  a.download = name;
  a.click();

  URL.revokeObjectURL(url);
}


async function deleteObject(oid, name) {

  if (!confirm(
    `Delete "${name}" and ALL its versions?`
  ))
    return;

  try {

    await api(
      `/objects/${oid}`,
      { method: "DELETE" }
    );

    if (
      currentObject &&
      currentObject.id === Number(oid)
    )
      closeHistory();

    await loadFiles();
    await loadBuckets();

  } catch (e) {

    say(
      "fMsg",
      e.message,
      false
    );

  }
}


// ---------- version history ----------

function openHistory(oid, name) {

  currentObject = {
    id: oid,
    name
  };

  $("curObject").textContent = name;
  $("vMsg").textContent = "";

  $("verCard").classList.remove("hidden");

  loadVersions();
}


function closeHistory() {

  currentObject = null;

  $("verCard").classList.add("hidden");
}


$("verClose").onclick = closeHistory;


async function loadVersions() {

  if (!currentObject) return;

  let vs;

  try {

    vs = await api(
      `/objects/${currentObject.id}/versions`
    );

  } catch (e) {

    return closeHistory();

  }

  if (!vs.length)
    return closeHistory();

  $("versions").innerHTML =
    vs.map(v => `

      <tr>

        <td>
          <span class="pill ${v.is_latest ? "tag-latest" : ""}">
            v${v.version_no}${v.is_latest ? " current" : ""}
          </span>
        </td>

        <td>
          ${fmtSize(v.size_bytes)}
        </td>

        <td>
          ${fmtDate(v.uploaded_at)}
        </td>

        <td class="muted">
          ${esc(v.sha_short)}…
        </td>

        <td class="row">

          <button
            data-act="dl"
            data-vid="${v.id}"
            data-name="${esc(currentObject.name)}"
          >
            Download
          </button>

          <button
            data-act="share"
            data-vid="${v.id}"
            data-label="${esc(currentBucket.name)}/${esc(currentObject.name)}@v${v.version_no}"
          >
            Share
          </button>

          ${
            v.is_latest || !currentBucket.versioning
              ? ""
              : `
                <button
                  data-act="restore"
                  data-vid="${v.id}"
                  data-no="${v.version_no}"
                >
                  Restore
                </button>
              `
          }

          <button
            class="danger"
            data-act="delver"
            data-vid="${v.id}"
            data-no="${v.version_no}"
          >
            Delete
          </button>

        </td>

      </tr>

    `).join("");
}


$("versions").onclick = async e => {

  const b =
    e.target.closest("button");

  if (!b) return;
  if (b.dataset.act === "share") return;   // handled in share.js
  try {

    if (b.dataset.act === "dl")
      return downloadVersion(
        b.dataset.vid,
        b.dataset.name
      );


    if (b.dataset.act === "restore") {

      const r = await api(
        `/versions/${b.dataset.vid}/restore`,
        { method: "POST" }
      );

      say(
        "vMsg",
        `Restored v${b.dataset.no}. It is now the current version (v${r.new_version}).`,
        true
      );
    }


    if (b.dataset.act === "delver") {

      if (!confirm(
        `Permanently delete version v${b.dataset.no}?`
      ))
        return;

      await api(
        `/versions/${b.dataset.vid}`,
        { method: "DELETE" }
      );

      say(
        "vMsg",
        `Deleted v${b.dataset.no}.`,
        true
      );
    }

    await loadVersions();
    await loadFiles();
    await loadBuckets();

  } catch (err) {

    say(
      "vMsg",
      err.message,
      false
    );

  }
};


// ---------- lifecycle time machine ----------

async function runLifecycle(dry) {

  const days =
    Number($("tmDays").value || 0);

  $("tmList").innerHTML = "";

  try {

    const r = await api(
      `/lifecycle/run?days=${days}&dry_run=${dry}`,
      { method: "POST" }
    );

    if (!r.expired.length) {

      say(
        "tmMsg",
        `After ${days} days, nothing ${dry ? "would expire" : "expired"}.`,
        true
      );

    } else {

      say(
        "tmMsg",
        `After ${days} days, ${r.expired.length} version(s) ${dry ? "WOULD expire (preview only)" : "expired and were deleted"}:`,
        true
      );

      $("tmList").innerHTML =
        r.expired
          .map(x =>
            `<li>${esc(x.bucket)}/${esc(x.key)} v${x.version}</li>`
          )
          .join("");
    }

    if (!dry) {

      await loadBuckets();

      if (currentBucket)
        await loadFiles();

      await loadVersions();
    }

  } catch (e) {

    say(
      "tmMsg",
      e.message,
      false
    );

  }
}


$("tmPreview").onclick =
  () => runLifecycle(true);


$("tmRun").onclick = () => {

  if (
    confirm(
      "Really delete all expired versions?"
    )
  )
    runLifecycle(false);

};


loadBuckets();
