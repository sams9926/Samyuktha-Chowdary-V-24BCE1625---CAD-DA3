// ======================= SHARE UI =======================

let shareVersionId = null;


// Local helpers — share.js does not depend on app.js
function shareGet(id) {
    return document.getElementById(id);
}


function shareEsc(s) {
    return String(s).replace(/[&<>"']/g, c =>
        ({
            "&": "&amp;",
            "<": "&lt;",
            ">": "&gt;",
            '"': "&quot;",
            "'": "&#39;"
        }[c])
    );
}


function shareSay(id, text, ok) {
    shareGet(id).className =
        "msg " + (ok ? "ok" : "err");

    shareGet(id).textContent = text;
}


function copyText(text) {

    if (
        navigator.clipboard &&
        window.isSecureContext
    ) {
        return navigator.clipboard.writeText(text);
    }

    const t =
        document.createElement("textarea");

    t.value = text;

    document.body.appendChild(t);

    t.select();

    document.execCommand("copy");

    t.remove();

    return Promise.resolve();
}


// ======================= OPEN SHARE CARD =======================

function openShare(vid, label) {

    shareVersionId = Number(vid);

    shareGet("shLabel").textContent = label;

    shareGet("shMsg").textContent = "";

    shareGet("shResult").classList.add("hidden");

    shareGet("shareCard").classList.remove("hidden");

    shareGet("shareCard").scrollIntoView({
        behavior: "smooth",
        block: "center"
    });
}


// ======================= SHARE BUTTONS =======================

document.addEventListener("click", e => {

    const b =
        e.target.closest(
            'button[data-act="share"]'
        );

    if (b) {

        openShare(
            b.dataset.vid,
            b.dataset.label
        );

    }

});


// ======================= CLOSE =======================

shareGet("shClose").onclick = () =>
    shareGet("shareCard").classList.add("hidden");


// ======================= CREATE SHARE =======================

shareGet("shCreate").onclick = async () => {

    try {

        const r = await api(
            `/versions/${shareVersionId}/share`,
            {
                method: "POST",

                body: JSON.stringify({
                    recipient:
                        shareGet("shRecipient").value,

                    hours:
                        Number(
                            shareGet("shHours").value
                        ),

                    max_views:
                        Number(
                            shareGet("shViews").value
                        ),

                    send_email:
                        shareGet("shEmail").checked
                })
            }
        );


        shareGet("shLink").value = r.link;

        shareGet("shResult")
            .classList
            .remove("hidden");


        if (r.email_error) {

            shareSay(
                "shMsg",
                "Link created, but the email failed: " +
                r.email_error,
                false
            );

        }

        else {

            shareSay(
                "shMsg",

                r.email_sent
                    ? "Link created and emailed."
                    : "Link created. Copy it and send it.",

                true
            );

        }


        loadShares();

    }

    catch (e) {

        shareSay(
            "shMsg",
            e.message,
            false
        );

    }

};


// ======================= COPY CREATED LINK =======================

shareGet("shCopy").onclick = async () => {

    await copyText(
        shareGet("shLink").value
    );

    shareSay(
        "shMsg",
        "Link copied.",
        true
    );

};


// ======================= SHARE STATES =======================

const STATE_LABEL = {

    active: "Active",

    expired: "Expired",

    revoked: "Revoked",

    exhausted: "Used up",

    gone: "File deleted"

};


// ======================= LOAD SHARES =======================

async function loadShares() {

    let rows;

    try {

        rows = await api("/shares");

    }

    catch (e) {

        return;

    }

    if (!rows)
        return;


    shareGet("shares").innerHTML =

        rows.length

            ? rows.map(s => `

                <tr>

                    <td>
                        ${shareEsc(s.recipient)}
                    </td>

                    <td>
                        ${shareEsc(
                            s.file_label || "—"
                        )}
                    </td>

                    <td>
                        ${s.view_count} /
                        ${s.max_views}
                    </td>

                    <td>
                        ${new Date(
                            s.expires_at * 1000
                        ).toLocaleString()}
                    </td>

                    <td>

                        <span
                            class="pill st-${s.state}"
                        >
                            ${STATE_LABEL[s.state]}
                        </span>

                    </td>

                    <td class="row">

                        ${
                            s.state === "active"

                            ? `

                                <button
                                    data-sact="copy"
                                    data-link="${shareEsc(s.link)}"
                                >
                                    Copy link
                                </button>

                                <button
                                    class="danger"
                                    data-sact="revoke"
                                    data-id="${s.id}"
                                >
                                    Revoke
                                </button>

                              `

                            : ""

                        }

                    </td>

                </tr>

            `).join("")

            : `

                <tr>

                    <td
                        colspan="6"
                        class="muted"
                    >
                        No links yet.
                        Click Share on any file.
                    </td>

                </tr>

            `;

}


// ======================= SHARE TABLE ACTIONS =======================

shareGet("shares").onclick = async e => {

    const b =
        e.target.closest("button");

    if (!b)
        return;


    // Copy link
    if (b.dataset.sact === "copy") {

        await copyText(
            b.dataset.link
        );

        b.textContent = "Copied ✓";

        setTimeout(
            () => b.textContent = "Copy link",
            1200
        );

    }


    // Revoke link
    if (b.dataset.sact === "revoke") {

        if (
            !confirm(
                "Revoke this link? It stops working immediately."
            )
        ) {
            return;
        }


        try {

            await api(
                `/shares/${b.dataset.id}/revoke`,
                {
                    method: "POST"
                }
            );

            loadShares();

        }

        catch (err) {

            alert(err.message);

        }

    }

};


// Initial load
loadShares();


// Refresh share states every 5 seconds
setInterval(
    loadShares,
    5000
);