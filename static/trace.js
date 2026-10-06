// Uses $, esc, say, fmtDate from app.js

const T_STATE = {
  active: "Link still active",
  expired: "Link expired",
  revoked: "Link revoked",
  exhausted: "Link used up",
  gone: "Original file deleted"
};

$("trRun").onclick = async () => {
  const f = $("trFile").files[0];

  $("trResult").innerHTML = "";

  if (!f) {
    return say(
      "trMsg",
      "Choose the suspected leaked file first.",
      false
    );
  }

  const fd = new FormData();
  fd.append("file", f);

  say("trMsg", "Analysing…", true);

  try {
    const r = await api("/trace", {
      method: "POST",
      body: fd
    });

    if (!r.found) {
      say(
        "trMsg",
        "No fingerprint found in this file.",
        false
      );

      $("trResult").innerHTML =
        `<p class="muted">${esc(r.hint)}</p>`;

      return;
    }

    say("trMsg", "Fingerprint found.", true);

    const rows = r.views.length
      ? r.views
          .map(v =>
            `<tr>
              <td>${fmtDate(v.ts)}</td>
              <td class="muted">${esc(v.details)}</td>
            </tr>`
          )
          .join("")
      : `<tr>
           <td colspan="2" class="muted">
             No view entries recorded.
           </td>
         </tr>`;

    $("trResult").innerHTML = `
      <div class="tracebox">
        <p class="muted" style="margin:0">
          This copy was issued to
        </p>

        <h2>${esc(r.recipient)}</h2>

        <p style="margin:4px 0">
          File: <b>${esc(r.file_label || "—")}</b>
        </p>

        <p style="margin:4px 0">
          Shared on: ${fmtDate(r.shared_at)}
          · Link #${r.share_id}
          · ${esc(T_STATE[r.state] || r.state)}
        </p>

        <h3 style="margin-top:14px">
          When this recipient opened it
        </h3>

        <table>
          <thead>
            <tr>
              <th>Time</th>
              <th>Details</th>
            </tr>
          </thead>

          <tbody>
            ${rows}
          </tbody>
        </table>
      </div>
    `;

    if (typeof loadShares === "function") {
      loadShares();
    }

  } catch (e) {
    say("trMsg", e.message, false);
  }
};