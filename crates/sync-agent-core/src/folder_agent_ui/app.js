/* global document, window, fetch */

const el = (id) => document.getElementById(id);

const pill = el("pill-status");
const btnRefresh = el("btn-refresh");
const list = el("list");
const empty = el("empty");
const errorBox = el("error");
const info = el("info");
const count = el("conflict-count");
const toggleDeleteCopies = el("toggle-delete-copies");

let refreshTimer = null;
let refreshing = false;

function setPill(text, cls) {
  pill.textContent = text;
  pill.classList.remove("ok", "bad");
  if (cls) pill.classList.add(cls);
}

function showError(message) {
  errorBox.hidden = false;
  errorBox.textContent = message;
  setPill("Error", "bad");
}

function clearError() {
  errorBox.hidden = true;
  errorBox.textContent = "";
}

async function fetchJson(url, options) {
  const res = await fetch(url, options);
  let data = null;
  const ct = res.headers.get("content-type") || "";
  if (ct.includes("application/json")) {
    data = await res.json();
  } else {
    data = await res.text();
  }
  if (!res.ok) {
    const msg =
      data && typeof data === "object" && data.error ? data.error : String(data);
    throw new Error(`${res.status} ${res.statusText}: ${msg}`);
  }
  return data;
}

function fmtWhen(ms) {
  try {
    return new Date(Number(ms)).toLocaleString();
  } catch (_) {
    return String(ms);
  }
}

function detailsPretty(value) {
  try {
    return JSON.stringify(value, null, 2);
  } catch (_) {
    return String(value);
  }
}

function conflictTitle(reason) {
  switch (reason) {
    case "dual_modify_conflict":
      return "Both changed (baseline known)";
    case "dual_modify_missing_baseline":
      return "Both changed (baseline missing)";
    case "modify_delete_conflict":
      return "Local modified, remote deleted";
    case "add_delete_ambiguous_missing_baseline":
      return "Local added, remote missing (baseline missing)";
    default:
      return reason;
  }
}

function createConflictCard(conflict, idx) {
  const card = document.createElement("div");
  card.className = "card";
  card.style.setProperty("--i", String(idx));

  const top = document.createElement("div");
  top.className = "row";

  const left = document.createElement("div");
  left.style.minWidth = "0";

  const path = document.createElement("div");
  path.className = "path";
  path.textContent = conflict.path;

  const reason = document.createElement("div");
  reason.className = "reason";
  reason.textContent = conflictTitle(conflict.reason);

  left.appendChild(path);
  left.appendChild(reason);

  const when = document.createElement("div");
  when.className = "when";
  when.textContent = fmtWhen(conflict.created_unix_ms);

  top.appendChild(left);
  top.appendChild(when);

  const actions = document.createElement("div");
  actions.className = "actions";

  const supported = new Set(conflict.supported_strategies || []);

  const btnKeepLocal = document.createElement("button");
  btnKeepLocal.className = "btn primary";
  btnKeepLocal.type = "button";
  btnKeepLocal.textContent = "Keep Local";
  btnKeepLocal.disabled = !supported.has("keep-local");
  btnKeepLocal.onclick = async () => {
    await resolveConflict(conflict.path, "keep-local");
  };

  const btnKeepRemote = document.createElement("button");
  btnKeepRemote.className = "btn danger";
  btnKeepRemote.type = "button";
  btnKeepRemote.textContent = "Keep Remote";
  btnKeepRemote.disabled = !supported.has("keep-remote");
  btnKeepRemote.onclick = async () => {
    await resolveConflict(conflict.path, "keep-remote");
  };

  actions.appendChild(btnKeepLocal);
  actions.appendChild(btnKeepRemote);

  const details = document.createElement("details");
  details.className = "details";
  const summary = document.createElement("summary");
  summary.textContent = "Details";
  const pre = document.createElement("pre");
  pre.textContent = detailsPretty(conflict.details);
  details.appendChild(summary);
  details.appendChild(pre);

  card.appendChild(top);
  card.appendChild(actions);
  card.appendChild(details);

  return card;
}

async function loadInfo() {
  const data = await fetchJson("/api/info");

  const items = [
    ["root_dir", data.root_dir],
    ["server_base_url", data.server_base_url],
    ["prefix", data.prefix === null ? "(none)" : data.prefix],
    ["state_db_path", data.state_db_path],
  ];

  info.innerHTML = "";
  for (const [k, v] of items) {
    const item = document.createElement("div");
    item.className = "item";

    const kk = document.createElement("div");
    kk.className = "k";
    kk.textContent = k;

    const vv = document.createElement("div");
    vv.className = "v";
    vv.textContent = String(v);

    item.appendChild(kk);
    item.appendChild(vv);
    info.appendChild(item);
  }
}

async function loadConflicts() {
  if (refreshing) return;
  refreshing = true;

  try {
    clearError();
    setPill("Refreshing...", null);

    const data = await fetchJson("/api/conflicts");
    const conflicts = data.conflicts || [];

    count.textContent = String(conflicts.length);
    list.innerHTML = "";
    if (conflicts.length === 0) {
      empty.hidden = false;
      setPill("All clear", "ok");
      return;
    }

    empty.hidden = true;
    conflicts.forEach((c, idx) => list.appendChild(createConflictCard(c, idx)));
    setPill(`${conflicts.length} pending`, null);
  } catch (err) {
    showError(err && err.message ? err.message : String(err));
  } finally {
    refreshing = false;
  }
}

async function resolveConflict(path, strategy) {
  const deleteCopies = !!toggleDeleteCopies.checked;

  const buttons = Array.from(list.querySelectorAll("button.btn"));
  buttons.forEach((b) => (b.disabled = true));

  try {
    clearError();
    setPill("Resolving...", null);
    await fetchJson("/api/conflicts/resolve", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        path,
        strategy,
        delete_conflict_copies: deleteCopies,
      }),
    });
    await loadConflicts();
  } catch (err) {
    showError(err && err.message ? err.message : String(err));
  } finally {
    await loadConflicts();
  }
}

function startAutoRefresh() {
  if (refreshTimer) window.clearInterval(refreshTimer);
  refreshTimer = window.setInterval(loadConflicts, 3500);
}

btnRefresh.onclick = async () => {
  await loadConflicts();
};

window.addEventListener("load", async () => {
  try {
    await loadInfo();
  } catch (err) {
    showError(err && err.message ? err.message : String(err));
  }
  await loadConflicts();
  startAutoRefresh();
});

