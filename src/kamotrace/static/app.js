"use strict";
const $ = (id) => document.getElementById(id);
let meta,
  table,
  lastResult,
  lastHistogram,
  lastContext,
  lastSelection,
  cellFilter,
  nextPage = 2,
  loadingMore = false,
  loadingFirst = true,
  summaryRequest = 0,
  updating = false,
  latestQuery = 0,
  latestApply = 0;
const number = (n) => new Intl.NumberFormat("en-US").format(n);
const local = (ms) => {
  const parts = Object.fromEntries(
    new Intl.DateTimeFormat("en-GB", {
      timeZone: meta.timezone,
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hourCycle: "h23",
    })
      .formatToParts(new Date(ms))
      .map((p) => [p.type, p.value]),
  );
  return `${parts.year}-${parts.month}-${parts.day}T${parts.hour}:${parts.minute}:${parts.second}`;
};
const shown = (ms) => local(ms).replace("T", " ");
const epoch = (value) => {
  const wall = Date.parse(value + "Z");
  if (!Number.isFinite(wall)) return NaN;
  const matches = new Set();
  for (const delta of [-86400000, 0, 86400000]) {
    const probe = wall + delta;
    const offset = Date.parse(local(probe) + "Z") - probe;
    const candidate = wall - offset;
    if (local(candidate) === value) matches.add(candidate);
  }
  // Reject nonexistent or ambiguous DST wall times rather than silently shifting evidence ranges.
  return matches.size === 1 ? [...matches][0] : NaN;
};
const inputTime = (ms) => {
  if (epoch(local(ms)) === ms) return shown(ms);
  const offset = (Date.parse(local(ms) + "Z") - ms) / 60000;
  return (
    shown(ms) +
    (offset < 0 ? "-" : "+") +
    String(Math.floor(Math.abs(offset) / 60)).padStart(2, "0") +
    ":" +
    String(Math.abs(offset) % 60).padStart(2, "0")
  );
};
const displayTime = (value) =>
  Number.isFinite(Date.parse(value))
    ? shown(Date.parse(value)) + " " + meta.timezone
    : "Unknown time";
// Explicit offsets also allow selecting either occurrence of a repeated DST hour.
const parseInput = (value) => {
  if (
    /^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}(:\d{2})?(Z|[+-]\d{2}:\d{2})$/.test(
      value.trim(),
    )
  )
    return Date.parse(value.trim().replace(" ", "T"));
  const m = /^\s*(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2})(:\d{2})?\s*$/.exec(value);
  return m ? epoch(`${m[1]}T${m[2]}${m[3] || ":00"}`) : NaN;
};
let reviews = { annotations: [], tags: [] },
  editingNote = null;
const selectedEvents = new Set();
let reviewHashes = [],
  noteMenuHashes = [],
  quickTagHashes = [];
let commandKey = null,
  commandsActive = false,
  commandPage = 1,
  commandRequest = 0,
  commandDetailRequest = 0;
let commandLog = false,
  logPage = 1,
  logTotal = 0,
  logBusy = false,
  logSelection,
  logFailure,
  logObserver,
  commandSheet = false,
  sheetTable,
  sheetRequest = 0,
  sheetPage = 1,
  sheetTotal = 0,
  sheetBusy = false,
  sheetSelection;

// ---- Applied query state and Back/Forward history -------------------------------------------
// The grid, counts, histograms and prevalence always describe `applied`. Inputs are a draft
// until Run; every pivot replaces `applied` and pushes the previous state onto the history.
let applied = null,
  editingFilter = null,
  expandedNotes = new Set(),
  noteScope = null,
  detailRow = null;
const queryHistory = [];
let historyPos = -1;
const noteEvents = new Map();
const OPS = {
  eq: ["is", "="],
  neq: ["is not", "≠"],
  in: ["is one of (comma-separated)", "∈"],
  contains: ["contains", "contains"],
  not_contains: ["does not contain", "excludes"],
  empty: ["is empty", "is empty"],
  not_empty: ["is not empty", "is not empty"],
  missing: ["is missing (null)", "is missing"],
  not_missing: ["is not missing (null)", "is present"],
};
const VALUELESS = ["empty", "not_empty", "missing", "not_missing"];

function normalize(state) {
  const s = state || {};
  const start = Number(s.start),
    end = Number(s.end);
  return {
    timezone: meta.timezones.includes(s.timezone) ? s.timezone : meta.timezone,
    start: Number.isFinite(start) ? start : meta.start_ms,
    end: Number.isFinite(end) ? end : meta.end_ms,
    search: typeof s.search === "string" ? s.search : "",
    filters: (Array.isArray(s.filters) ? s.filters : [])
      .filter((f) => f && meta.fields[f.field] && OPS[f.op])
      .map((f) => ({ field: f.field, op: f.op, value: String(f.value ?? "") })),
    tags: (Array.isArray(s.tags) ? s.tags : []).filter(
      (t) => typeof t === "string",
    ),
    annotation_id: Number.isInteger(s.annotation_id) ? s.annotation_id : null,
    rules: (Array.isArray(s.rules) ? s.rules : []).filter(
      (r) => typeof r === "string",
    ),
    // Agents can save a minimum Sigma level with a note; keep it so Reopen query matches their result.
    min_level: meta.levels.includes(s.min_level) ? s.min_level : null,
    command_key: typeof s.command_key === "string" ? s.command_key : null,
    command_label: typeof s.command_label === "string" ? s.command_label : null,
  };
}

async function apply(state, push = true) {
  const requestId = ++latestApply;
  const next = normalize(state);
  if (!(next.start < next.end)) {
    error("Choose a valid time range: start must be before the exclusive end.");
    return;
  }
  if (next.timezone !== meta.timezone) {
    try {
      const result = await request("/api/meta", { timezone: next.timezone });
      if (requestId !== latestApply) return;
      meta = result;
    } catch (e) {
      if (requestId !== latestApply) return;
      error(e.message);
      $("timezone").value = meta.timezone;
      return;
    }
    localStorage.setItem("timezone", meta.timezone);
    noteEvents.clear();
    document.querySelectorAll("dialog[open]").forEach((d) => d.close());
    if (commandKey) openCommand(commandKey, true);
  }
  $("timezone").value = meta.timezone;
  $("start").setAttribute("aria-label", `From (inclusive), ${meta.timezone}`);
  $("end").setAttribute("aria-label", `Until (exclusive), ${meta.timezone}`);
  $("coverage").textContent =
    `${number(meta.total)} events · ${local(meta.start_ms).slice(0, 10)} to ${local(meta.end_ms).slice(0, 10)} ${meta.timezone}`;
  timeline();
  if (push && JSON.stringify(next) !== JSON.stringify(applied)) {
    queryHistory.splice(historyPos + 1);
    queryHistory.push(next);
    historyPos = queryHistory.length - 1;
  }
  applied = next;
  closeFilterEditor();
  syncInputs();
  renderScopes();
  renderTags();
  renderNotes();
  renderDetections();
  $("back").disabled = historyPos <= 0;
  $("forward").disabled = historyPos >= queryHistory.length - 1;
  reload();
}

function go(step) {
  const pos = historyPos + step;
  if (pos < 0 || pos >= queryHistory.length) return;
  historyPos = pos;
  apply(queryHistory[pos], false);
}

function query() {
  return {
    timezone: applied.timezone,
    start: new Date(applied.start).toISOString(),
    end: new Date(applied.end).toISOString(),
    search: applied.search,
    tags: applied.tags,
    annotation_id: applied.annotation_id,
    rules: applied.rules,
    min_level: applied.min_level,
    command_key: applied.command_key,
    filters: applied.filters,
  };
}

function syncInputs() {
  $("search").value = applied.search;
  $("start").value = inputTime(applied.start);
  $("end").value = inputTime(applied.end);
  updating = true;
  $("time-slider").noUiSlider.set([applied.start, applied.end]);
  updating = false;
  paintSelection();
  draftState();
}

function draft() {
  return {
    ...applied,
    search: $("search").value,
    start: parseInput($("start").value),
    end: parseInput($("end").value),
  };
}

function draftState() {
  const d = draft();
  const dirty =
    d.search !== applied.search ||
    d.start !== applied.start ||
    d.end !== applied.end ||
    (!$("filter-editor").hidden && filterEditorValue() !== null);
  $("query-state").textContent = dirty ? "Draft · Run to apply" : "Applied";
  $("query-state").className = "state " + (dirty ? "draft" : "applied");
  $("revert").hidden = !dirty;
  if (dirty) $("run").classList.add("pulse");
  else $("run").classList.remove("pulse");
}

function runDraft() {
  const d = draft();
  if (!Number.isFinite(d.start) || !Number.isFinite(d.end)) {
    error(
      `Use YYYY-MM-DD HH:MM:SS in ${meta.timezone}. For repeated DST times, include an offset (e.g. -04:00); nonexistent times are invalid.`,
    );
    return;
  }
  const pending = filterEditorValue();
  if (pending) {
    const filters = [...applied.filters];
    if (editingFilter === null) filters.push(pending);
    else filters[editingFilter] = pending;
    d.filters = filters;
  }
  apply(d);
}

function chip(text, { title, onRemove, onClick, swatch, kind } = {}) {
  const span = document.createElement("span");
  span.className = "scope" + (kind ? " scope-" + kind : "");
  const label = document.createElement(onClick ? "button" : "span");
  if (onClick) {
    label.type = "button";
    label.onclick = onClick;
  }
  label.className = "scope-label";
  if (swatch) {
    const s = document.createElement("span");
    s.className = "swatch";
    s.style.backgroundColor = swatch;
    label.append(s);
  }
  label.append(text);
  if (title) span.title = title;
  span.append(label);
  if (onRemove) {
    const x = document.createElement("button");
    x.type = "button";
    x.className = "scope-remove";
    x.textContent = "×";
    x.setAttribute("aria-label", `Remove ${text}`);
    x.onclick = onRemove;
    span.append(x);
  }
  return span;
}

function noteTitle(note) {
  const line = (note?.body || "").split("\n").find((l) => l.trim()) || "";
  return (
    line
      .replace(/^[#>*\-\s]+/, "")
      .replace(/[*_`]/g, "")
      .slice(0, 90) || `Finding #${note?.id}`
  );
}

function renderScopes() {
  const s = applied,
    out = [];
  const full = s.start === meta.start_ms && s.end === meta.end_ms;
  out.push(
    chip(`${shown(s.start)} → ${shown(s.end)} ${meta.timezone}`, {
      kind: "time",
      title: full
        ? "Whole export. Click to adjust the time range."
        : "Time range [from, until). Click to adjust; × resets to the whole export.",
      onClick: () => $("start").focus(),
      onRemove: full
        ? null
        : () => apply({ ...s, start: meta.start_ms, end: meta.end_ms }),
    }),
  );
  if (s.search)
    out.push(
      chip(`Search “${s.search}”`, {
        title: "Literal, case-insensitive substring of the raw event",
        onRemove: () => apply({ ...s, search: "" }),
      }),
    );
  s.filters.forEach((f, i) =>
    out.push(
      chip(
        `${meta.fields[f.field]} ${OPS[f.op][1]}${VALUELESS.includes(f.op) ? "" : " " + (f.value === "" ? "(empty string)" : f.value)}`,
        {
          title: "Click to edit this filter",
          onClick: () => openFilterEditor(i),
          onRemove: () =>
            apply({ ...s, filters: s.filters.filter((_, j) => j !== i) }),
        },
      ),
    ),
  );
  for (const slug of s.tags) {
    const tag = reviews.tags.find((t) => t.slug === slug);
    out.push(
      chip(slug, {
        kind: "tag",
        swatch: tag?.color || "#999",
        title: "Tag filter: events must have every selected tag",
        onRemove: () => apply({ ...s, tags: s.tags.filter((t) => t !== slug) }),
      }),
    );
  }
  if (s.tags.length > 1) {
    const all = document.createElement("span");
    all.className = "hint";
    all.textContent = "(all tags must match)";
    out.push(all);
  }
  if (s.annotation_id !== null) {
    const note = reviews.annotations.find((n) => n.id === s.annotation_id);
    out.push(
      chip(
        `Finding #${s.annotation_id}: ${note ? noteTitle(note) : "deleted"}`,
        {
          kind: "note",
          title:
            "Events linked to this finding. Click to show it in the sidebar.",
          onClick: () => showNotes([s.annotation_id]),
          onRemove: () => apply({ ...s, annotation_id: null }),
        },
      ),
    );
  }
  for (const id of s.rules) {
    const rule = detections.rules.find((r) => r.rule_id === id);
    out.push(
      chip(`Sigma: ${rule ? rule.title : id}`, {
        kind: "rule",
        title:
          "Suzaku detection (Sigma rule " +
          id +
          "). Several rule scopes must all match.",
        onClick: () => sidebarTab("detections"),
        onRemove: () => apply({ ...s, rules: s.rules.filter((r) => r !== id) }),
      }),
    );
  }
  if (s.min_level !== null)
    out.push(
      chip(`Sigma ≥ ${s.min_level}`, {
        kind: "rule",
        title: `Only events with a Suzaku detection at level ${s.min_level} or above.`,
        onClick: () => sidebarTab("detections"),
        onRemove: () => apply({ ...s, min_level: null }),
      }),
    );
  if (s.command_key !== null)
    out.push(
      chip(`SSM command ${s.command_label || s.command_key}`, {
        kind: "command",
        title: "Exact command ID, account and region linkage",
        onClick: () => {
          switchView(true);
          openCommand(s.command_key);
        },
        onRemove: () => apply({ ...s, command_key: null, command_label: null }),
      }),
    );
  $("scopes").replaceChildren(...out);
}

// ---- Filter editor ---------------------------------------------------------------------------
function filterEditorValue() {
  const op = $("filter-op").value;
  const value = $("filter-value").value;
  if (!VALUELESS.includes(op) && value === "" && editingFilter === null)
    return null;
  return {
    field: $("filter-field").value,
    op,
    value: VALUELESS.includes(op) ? "" : value,
  };
}

function filterChoices() {
  $("filter-choices").replaceChildren(
    ...(meta.facets[$("filter-field").value] || []).map(
      (v) => new Option(v, v),
    ),
  );
  $("filter-value").disabled = VALUELESS.includes($("filter-op").value);
}

function openFilterEditor(index = null) {
  editingFilter = index;
  const f =
    index === null
      ? { field: "event_name", op: "eq", value: "" }
      : applied.filters[index];
  $("filter-field").value = f.field;
  $("filter-op").value = f.op;
  $("filter-value").value = f.value;
  $("filter-save").textContent = index === null ? "Add" : "Update";
  $("filter-editor").hidden = false;
  $("add-filter").hidden = true;
  filterChoices();
  $("filter-value").focus();
  draftState();
}

function closeFilterEditor() {
  $("filter-editor").hidden = true;
  $("add-filter").hidden = false;
  editingFilter = null;
}

function addFilter(field, op, value) {
  apply({ ...applied, filters: [...applied.filters, { field, op, value }] });
}

// ---- SSM commands (JSON-backed in memory; grouped by account + region + command ID) ----------
function commandQuery() {
  return {
    start: new Date(applied.start).toISOString(),
    end: new Date(applied.end).toISOString(),
    search: $("command-search").value,
  };
}

function commandLayout(sheet, log = false) {
  if (commandLog && !log) leaveLog();
  commandLog = log;
  commandSheet = sheet;
  ++commandRequest;
  ++sheetRequest;
  // A layout switch abandons any in-flight log request; let the next one start.
  logBusy = false;
  $("command-browser-panel").hidden = sheet || log;
  $("command-sheet-panel").hidden = !sheet;
  $("command-log-panel").hidden = !log;
  $("log-search-scope").hidden = !log;
  $("sheet-density-label").hidden = !sheet;
  $("command-sort").disabled = $("command-direction").disabled = sheet || log;
  $("command-search").placeholder = log
    ? "Search activity: commands, output, decoding, interpretations, tags, findings…"
    : "Search commands, decoded payloads, system IDs, output, identity…";
  $("command-detail-layout").setAttribute(
    "aria-pressed",
    String(!sheet && !log),
  );
  $("command-sheet-layout").setAttribute("aria-pressed", String(sheet));
  $("command-log-layout").setAttribute("aria-pressed", String(log));
  syncLogEditor();
  loadCommands();
}

// ---- Activity log: dense raw/enhanced reading lanes and one reusable side editor ----------
// Drafts live in logDrafts (keyed by entry_id), never only in DOM, so they survive appending pages,
// new searches, layout/tab switches and reopening the editor. They are not persisted (privacy);
// leaving the page with dirty drafts asks for confirmation instead.
const logDrafts = new Map();
const logCards = new Map(); // entry_id -> { row, card } for the displayed result only.
let logEditing = null,
  logPending = false,
  logStale = false,
  logLatest = null,
  logReturn = null,
  logFocus = null;

function logQuery() {
  return { ...commandQuery(), search_scope: $("log-search-scope").value };
}

const sameLogQuery = (a, b) =>
  ["start", "end", "search", "search_scope"].every((k) => a[k] === b[k]);

const logTags = (value) => [
  ...new Set(
    value
      .split(",")
      .map((t) => t.trim())
      .filter(Boolean),
  ),
];

function logDirty(draft) {
  return (
    draft.text !== draft.base.text ||
    draft.finding !== draft.base.finding ||
    logTags(draft.tags).sort().join() !== draft.base.tags.join()
  );
}

function logField(parent, label, value, className = "") {
  const field = document.createElement("div");
  field.className = "ssm-log-field " + className;
  const name = document.createElement("span");
  name.className = "ssm-log-label";
  name.textContent = label;
  const text = document.createElement("pre");
  text.textContent = value;
  field.append(name, text);
  parent.append(field);
}

function logLine(parent, text, className = "ssm-log-state") {
  const line = document.createElement("p");
  line.className = className;
  line.textContent = text;
  parent.append(line);
}

function logRaw(row) {
  const lane = document.createElement("div");
  lane.className = "ssm-log-raw";
  if (row.parameters === null) logLine(lane, "request: not collected");
  else
    logField(
      lane,
      row.operation === "Session metadata" ? "session metadata" : "request",
      row.parameters,
    );
  const states = { "not collected": [], "collected empty": [] };
  for (const [field, label] of [
    ["stdout", "stdout"],
    ["stderr", "stderr"],
    ["combined_output", "combined"],
  ]) {
    if (row[field] === null) states["not collected"].push(label);
    else if (row[field] === "") states["collected empty"].push(label);
    else
      logField(
        lane,
        field === "combined_output"
          ? "combined output (streams not separable)"
          : label,
        row[field],
        field === "stderr" ? "stderr" : "",
      );
  }
  // Missing and empty streams stay distinct, in one compact line.
  const summary = Object.entries(states)
    .filter(([, names]) => names.length)
    .map(([state, names]) => `${names.join(", ")}: ${state}`);
  if (summary.length) logLine(lane, summary.join(" · "));
  return lane;
}

function renderLogEnhanced(lane, row) {
  lane.replaceChildren();
  const review = row.review;
  if (row.decoded)
    logField(lane, "export decoding · derived, not raw", row.decoded);
  if (review.text) logField(lane, "interpretation · analyst", review.text);
  if (review.tags.length)
    logLine(lane, `entry tags: ${review.tags.join(", ")}`, "ssm-log-tags");
  if (review.finding) logField(lane, "entry finding", review.finding);
  for (const event of row.events) {
    if (event.tags?.length)
      logLine(
        lane,
        `event tags (${event.event_id}): ${event.tags.map((t) => t.slug).join(", ")}`,
        "ssm-log-tags event",
      );
    for (const finding of event.findings || [])
      logField(
        lane,
        `event finding #${finding.id} (${event.event_id})`,
        finding.body,
        "event",
      );
  }
  if (!review.text && !review.tags.length && !review.finding)
    logLine(lane, "No analyst review", "ssm-log-state");
  if (logDrafts.get(row.entry_id)?.dirty)
    logLine(lane, "Unsaved draft in editor", "ssm-log-draft");
}

function logEntry(row) {
  const card = document.createElement("article");
  card.className = "ssm-log-entry";
  card.dataset.entryId = row.entry_id;
  card.classList.toggle("editing", logEditing === row.entry_id);
  const head = document.createElement("header");
  const time = document.createElement("strong");
  time.textContent =
    row.time_ms === null
      ? "Unknown time"
      : `${shown(row.time_ms)} ${meta.timezone}`;
  const what = document.createElement("span");
  const failed =
    /fail|denied|timed ?out|cancel|error/i.test(row.status) ||
    (row.operation !== "Command output" && row.events.some((e) => e.error));
  what.className = failed ? "ssm-log-failed" : "";
  what.textContent = `${row.operation} · ${row.status}${row.response_code === null ? "" : " · exit " + row.response_code}`;
  const where = document.createElement("span");
  where.textContent = `${row.instance_id || "no exact machine collected"} · ${row.plugin ? "plugin " + row.plugin : "no plugin"}`;
  const edit = document.createElement("button");
  edit.type = "button";
  edit.className = "ssm-log-edit";
  edit.textContent = "Edit analyst entry";
  edit.onclick = () => openLogEditor(row.entry_id);
  head.append(time, what, where, edit);
  const context = document.createElement("p");
  context.className = "ssm-log-context";
  context.textContent = `${row.account || "unknown account"} · ${row.region || "unknown region"} · command ${row.command_id || "none"} · time basis: ${row.time_basis} · ${row.output_state}`;
  const lanes = document.createElement("div");
  lanes.className = "ssm-log-lanes";
  const enhanced = document.createElement("div");
  enhanced.className = "ssm-log-enhanced";
  renderLogEnhanced(enhanced, row);
  lanes.append(logRaw(row), enhanced);
  card.append(head, context, lanes);
  const links = document.createElement("div");
  links.className = "ssm-log-links";
  for (const event of row.events) {
    const button = document.createElement("button");
    button.type = "button";
    button.textContent = `${event.operation} · ${event.error || "no API error (not execution proof)"} · ${event.event_id} · ${event.source}`;
    button.onclick = async () => {
      try {
        if (event.id !== null) await detail({ id: event.id });
        else {
          const data = await request("/api/ssm-event", { key: event.key });
          detailRow = null;
          $("detail-id").textContent =
            `${data.event_id} · Supplemental SSM export`;
          $("raw-event").textContent = data.raw_json;
          $("record-hash").textContent =
            "Reconstructed from supplemental JSON, not original database evidence.";
          $("detail-findings").replaceChildren();
          $("detail-prev").hidden = $("detail-next").hidden = true;
          eventCommandLinks([]);
          openDetail();
        }
      } catch (e) {
        error(e.message);
      }
    };
    links.append(button);
  }
  const hashes = [
    ...new Set(row.events.map((e) => e.record_sha256).filter(Boolean)),
  ];
  if (hashes.length) {
    for (const [label, handler] of [
      ["Event tags", (b) => openQuickTag(b, hashes)],
      ["Event finding", (b) => openNoteMenu(b, hashes)],
    ]) {
      const button = document.createElement("button");
      button.type = "button";
      button.textContent = label;
      button.title = `Applies to ${hashes.length} linked evidence event${hashes.length === 1 ? "" : "s"}, not to this log entry`;
      button.onclick = () => handler(button);
      links.append(button);
    }
  }
  if (links.childElementCount) card.append(links);
  logCards.set(row.entry_id, { row, card });
  return card;
}

// The first entry whose bottom is below the viewport top, and its offset. Entries are in document
// order, so a binary search keeps this cheap with thousands loaded.
function logAnchor() {
  const cards = $("command-log").getElementsByClassName("ssm-log-entry");
  let low = 0,
    high = cards.length - 1,
    found = null;
  while (low <= high) {
    const mid = (low + high) >> 1;
    if (cards[mid].getBoundingClientRect().bottom > 0) {
      found = cards[mid];
      high = mid - 1;
    } else low = mid + 1;
  }
  return found
    ? {
        id: found.dataset.entryId,
        top: found.getBoundingClientRect().top,
        loaded: logCards.size,
      }
    : null;
}

function restoreLogAnchor(anchor) {
  const item = anchor && logCards.get(anchor.id);
  if (item) scrollBy(0, item.card.getBoundingClientRect().top - anchor.top);
  return Boolean(item);
}

// Patch only one entry's analyst lane, keeping the reader's place: no reload or forced scroll.
function patchLogRow(id, change) {
  const draft = logDrafts.get(id);
  if (draft) draft.row = { ...draft.row, ...change };
  const item = logCards.get(id);
  if (!item) return;
  item.row = { ...item.row, ...change };
  const anchor = logAnchor();
  renderLogEnhanced(item.card.querySelector(".ssm-log-enhanced"), item.row);
  restoreLogAnchor(anchor);
}

function markLogStale(message) {
  if (!logSelection?.review_dependent) return;
  logStale = true;
  logObserver.unobserve($("log-load-status"));
  $("log-load-status").textContent =
    `${message} Loaded entries and drafts are kept; refresh to continue past ${number(logCards.size)} loaded.`;
  const anchor = logAnchor(); // The Refresh button grows the header above the entries.
  $("refresh-log").hidden = false;
  restoreLogAnchor(anchor);
}

function logDraft(row) {
  let draft = logDrafts.get(row.entry_id);
  if (!draft) {
    const base = row.review;
    draft = {
      row,
      base,
      text: base.text,
      tags: base.tags.join(", "),
      finding: base.finding,
      dirty: false,
    };
    logDrafts.set(row.entry_id, draft);
  }
  return draft;
}

// Forget a clean draft once its entry is no longer being edited; dirty drafts stay.
function releaseLogDraft(id) {
  const draft = logDrafts.get(id);
  if (draft && !draft.dirty && id !== logEditing) logDrafts.delete(id);
  logCards.get(id)?.card.classList.toggle("editing", id === logEditing);
}

function renderLogDrafts() {
  const dirty = [...logDrafts.entries()].filter(([, d]) => d.dirty);
  $("log-draft-count").textContent = dirty.length;
  $("log-drafts").hidden = !dirty.length;
  $("log-draft-list").replaceChildren(
    ...dirty.map(([id, d]) => {
      const li = document.createElement("li");
      const b = document.createElement("button");
      b.type = "button";
      b.textContent = `${d.row.time_ms === null ? "Unknown time" : shown(d.row.time_ms)} · ${d.row.operation} · ${d.row.instance_id || "no machine"}${logCards.has(id) ? "" : " (not in current results)"}`;
      b.setAttribute("aria-current", String(id === logEditing));
      b.onclick = () => openLogEditor(id);
      li.append(b);
      return li;
    }),
  );
}

function renderLogEditor() {
  const draft = logDrafts.get(logEditing);
  if (!draft) return;
  const row = draft.row;
  $("log-editor-entry").textContent =
    `${row.time_ms === null ? "Unknown time" : shown(row.time_ms) + " " + meta.timezone} · ${row.operation} · ${row.status}\n${row.account || "unknown account"} · ${row.region || "unknown region"} · ${row.instance_id || "no exact machine"} · ${row.plugin || "no plugin"}\nEntry ${row.entry_id.slice(0, 12)}… · saved ${draft.base.updated || "never"}`;
  $("log-edit-text").value = draft.text;
  $("log-edit-tags").value = draft.tags;
  $("log-edit-finding").value = draft.finding;
  renderLogEditorState();
}

function renderLogEditorState() {
  const draft = logDrafts.get(logEditing);
  // Disabling the focused button drops focus to <body>; remember it so Escape/Tab keep working.
  const focused = document.activeElement;
  for (const id of [
    "log-save",
    "log-latest",
    "log-discard",
    "log-copy-raw",
    "log-use-latest",
    "log-replace-latest",
  ])
    $(id).disabled = logPending;
  if (!logPending && focused === document.body && logEditing)
    (logFocus || $("log-edit-text")).focus({ preventScroll: true });
  logFocus = logPending ? focused : null;
  $("log-editor-dirty").textContent = draft?.dirty
    ? "Unsaved draft"
    : "No unsaved changes";
  $("log-latest-panel").hidden = !(logLatest && logLatest.id === logEditing);
  renderLogDrafts();
}

function logEditorStatus(id, message) {
  if (id === logEditing) $("log-editor-status").textContent = message;
}

function syncLogEditor() {
  $("log-editor").hidden = !(commandsActive && commandLog && logEditing);
}

function openLogEditor(id) {
  const row = logCards.get(id)?.row || logDrafts.get(id)?.row;
  if (!row) return;
  const previous = logEditing;
  logEditing = id;
  if (previous) releaseLogDraft(previous);
  const draft = logDraft(row);
  if (logLatest?.id !== id) logLatest = null;
  logCards.get(id)?.card.classList.add("editing");
  renderLogEditor();
  $("log-editor-status").textContent = draft.dirty
    ? "Unsaved draft restored."
    : "";
  syncLogEditor();
  $("log-edit-text").focus({ preventScroll: true });
}

function closeLogEditor() {
  const id = logEditing;
  logEditing = null;
  logLatest = null;
  releaseLogDraft(id);
  syncLogEditor();
  renderLogDrafts();
  // Return to the entry without moving the page, so Page Down continues from here.
  logCards
    .get(id)
    ?.card.querySelector(".ssm-log-edit")
    .focus({ preventScroll: true });
}

function editLogDraft() {
  const draft = logDrafts.get(logEditing);
  if (!draft) return;
  draft.text = $("log-edit-text").value;
  draft.tags = $("log-edit-tags").value;
  draft.finding = $("log-edit-finding").value;
  const was = draft.dirty;
  draft.dirty = logDirty(draft);
  if (was !== draft.dirty) patchLogRow(logEditing, {});
  renderLogEditorState();
}

async function saveLogEntry() {
  const id = logEditing,
    draft = logDrafts.get(id);
  if (!draft || logPending) return;
  logPending = true;
  renderLogEditorState();
  try {
    const saved = await request("/api/ssm-log-review", {
      entry_id: id,
      updated: draft.base.updated,
      text: draft.text,
      tags: logTags(draft.tags),
      finding: draft.finding,
    });
    // Text typed while saving stays dirty: dirtiness is relative to the saved version.
    draft.base = saved;
    draft.dirty = logDirty(draft);
    if (logLatest?.id === id) logLatest = null;
    patchLogRow(id, { review: saved });
    logEditorStatus(
      id,
      draft.dirty
        ? "Saved. Edits made while saving are still unsaved."
        : "Saved separately; raw evidence unchanged.",
    );
    markLogStale("Saved analyst content may change which entries match.");
    releaseLogDraft(id);
  } catch (e) {
    logEditorStatus(
      id,
      `${e.message} Your draft is kept. Read latest saved, merge deliberately, then save.`,
    );
  } finally {
    logPending = false;
    renderLogEditorState();
  }
}

async function readLatestLog() {
  const id = logEditing;
  if (!id || logPending) return;
  logPending = true;
  renderLogEditorState();
  try {
    const [latest] = (await request("/api/ssm-log", { entry_id: id })).data;
    // The log shows saved state, so it can show the latest; the draft is never replaced silently.
    patchLogRow(id, { review: latest.review, events: latest.events });
    const draft = logDrafts.get(id);
    if (!draft) return;
    if (!draft.dirty) {
      Object.assign(draft, {
        base: latest.review,
        text: latest.review.text,
        tags: latest.review.tags.join(", "),
        finding: latest.review.finding,
      });
      if (id === logEditing) renderLogEditor();
      logEditorStatus(
        id,
        "No unsaved changes; editor shows the latest saved version.",
      );
    } else if (latest.review.updated === draft.base.updated)
      logEditorStatus(id, "Your draft is based on the latest saved version.");
    else {
      logLatest = { id, review: latest.review };
      $("log-latest-stamp").textContent = latest.review.updated || "deleted";
      $("log-latest-text").textContent = latest.review.text || "(empty)";
      $("log-latest-tags").textContent =
        `Entry tags: ${latest.review.tags.join(", ") || "none"}`;
      $("log-latest-finding").textContent = latest.review.finding || "(empty)";
      logEditorStatus(
        id,
        "Someone else saved this entry. Compare, merge into your draft, then choose a merge base.",
      );
    }
  } catch (e) {
    logEditorStatus(id, e.message);
  } finally {
    logPending = false;
    renderLogEditorState();
  }
}

function adoptLatestLog(replace) {
  const draft = logDrafts.get(logEditing);
  if (!draft || !logLatest || logLatest.id !== logEditing) return;
  if (replace && !confirm("Replace your draft with the latest saved version?"))
    return;
  draft.base = logLatest.review;
  if (replace)
    Object.assign(draft, {
      text: draft.base.text,
      tags: draft.base.tags.join(", "),
      finding: draft.base.finding,
    });
  draft.dirty = logDirty(draft);
  logLatest = null;
  renderLogEditor();
  patchLogRow(logEditing, {});
  $("log-editor-status").textContent = replace
    ? "Draft replaced with the latest saved version."
    : "Your draft now replaces the latest saved version when saved. Check it includes their changes.";
}

function discardLogDraft() {
  const draft = logDrafts.get(logEditing);
  if (!draft || (draft.dirty && !confirm("Discard this unsaved draft?")))
    return;
  Object.assign(draft, {
    text: draft.base.text,
    tags: draft.base.tags.join(", "),
    finding: draft.base.finding,
    dirty: false,
  });
  renderLogEditor();
  patchLogRow(logEditing, {});
  $("log-editor-status").textContent = "Draft discarded.";
}

function copyRawToLog() {
  const draft = logDrafts.get(logEditing);
  if (!draft) return;
  const input = $("log-edit-text");
  if (
    input.value &&
    !confirm("Replace the current interpretation draft with raw text?")
  )
    return;
  const row = draft.row;
  input.value = [row.parameters, row.stdout, row.stderr, row.combined_output]
    .filter((v) => v !== null && v !== "")
    .join("\n\n");
  editLogDraft();
}

function decodeLog(encoding) {
  const input = $("log-edit-text");
  const start = input.selectionStart,
    end = input.selectionEnd;
  const encoded = (
    start === end ? input.value : input.value.slice(start, end)
  ).replace(/\s/g, "");
  try {
    const bytes = Uint8Array.from(atob(encoded), (c) => c.charCodeAt(0));
    const decoded = new TextDecoder(encoding, { fatal: true }).decode(bytes);
    if (start === end) input.value = decoded;
    else input.setRangeText(decoded, start, end, "select");
    editLogDraft();
    $("log-editor-status").textContent =
      "Decoded as data only. Review the interpretation before saving.";
  } catch {
    $("log-editor-status").textContent =
      `Not valid Base64 ${encoding} text; draft unchanged.`;
  }
}

// Event tag/finding writes (from any view) patch linked log events in place. A review-dependent
// search may now match differently, so say so instead of continuing with shifted pages.
function patchLogEvents(body, result) {
  const hashes = new Set(body.hashes || []);
  const tag = reviews.tags.find((t) => t.slug === body.slug);
  const id = body.action === "annotate" ? result.id : body.id;
  const note = reviews.annotations.find((n) => n.id === id);
  for (const [entryId, { row }] of logCards) {
    let changed = false;
    const events = row.events.map((event) => {
      const hit = hashes.has(event.record_sha256);
      let tags = event.tags,
        findings = event.findings;
      if (
        body.action === "tag" &&
        hit &&
        !tags.some((t) => t.slug === body.slug)
      )
        tags = [...tags, { slug: body.slug, color: tag.color }].sort((a, b) =>
          a.slug.localeCompare(b.slug),
        );
      if (body.action === "untag" && hit)
        tags = tags.filter((t) => t.slug !== body.slug);
      if (["annotate", "link"].includes(body.action) && hit && note)
        findings = [...findings.filter((f) => f.id !== id), note].sort(
          (a, b) => a.id - b.id,
        );
      if ((body.action === "unlink" && hit) || body.action === "delete")
        findings = findings.filter((f) => f.id !== id);
      if (body.action === "edit" && note)
        findings = findings.map((f) => (f.id === id ? note : f));
      if (tags === event.tags && findings === event.findings) return event;
      changed = true;
      return { ...event, tags, findings };
    });
    if (changed) patchLogRow(entryId, { events });
  }
  if (logSelection && result.log_revision !== logSelection.revision)
    markLogStale("Event tags or findings linked to this log changed.");
}

function leaveLog() {
  if (!$("command-log-panel").hidden) logReturn = logAnchor();
  logObserver.unobserve($("log-load-status"));
}

function logStatus() {
  const loaded = logCards.size;
  $("command-status").textContent =
    `${number(logTotal)} activity entries · oldest first · ${number(loaded)} loaded`;
  if (logStale) return;
  $("log-load-status").textContent =
    `${number(loaded)} / ${number(logTotal)} entries loaded · ${loaded < logTotal ? "Keep scrolling for more" : "All matching activity loaded"}`;
  if (loaded < logTotal) logObserver.observe($("log-load-status"));
}

// Returning to an unchanged applied selection reuses loaded entries and the reading position.
function resumeLog() {
  logStatus();
  const anchor = logReturn;
  logReturn = null;
  if (anchor) requestAnimationFrame(() => restoreLogAnchor(anchor));
}

async function loadLog({ more = false, retry = null, fresh = false } = {}) {
  if (
    more &&
    (logBusy ||
      logStale ||
      !commandsActive ||
      !commandLog ||
      logPage * 100 >= logTotal)
  )
    return;
  if (
    !more &&
    !retry &&
    !fresh &&
    logSelection &&
    !logFailure &&
    sameLogQuery(logQuery(), logSelection)
  )
    return resumeLog();
  let selection = retry ? retry.selection : more ? logSelection : logQuery();
  let page = retry ? retry.page : more ? logPage + 1 : 1;
  const restore = retry?.restore;
  const token = ++commandRequest;
  logBusy = true;
  logObserver.unobserve($("log-load-status"));
  $("more-log").hidden = $("refresh-log").hidden = true;
  $("more-log").disabled = true;
  $("log-load-status").textContent = "Loading activity…";
  if (page === 1) $("command-status").textContent = "Loading activity…";
  try {
    for (;;) {
      const { start, end, search, search_scope, revision } = selection;
      const result = await request("/api/ssm-log", {
        start,
        end,
        search,
        search_scope,
        page,
        ...(page > 1 ? { revision } : {}),
      });
      if (token !== commandRequest) return;
      if (page === 1) {
        selection = {
          ...selection,
          revision: result.revision,
          review_dependent: result.review_dependent,
        };
        logCards.clear();
        logStale = false;
        $("command-log").replaceChildren();
        if (!result.total)
          $("command-log").textContent =
            "No matching activity. Widen the time range, change the search scope or clear search.";
      }
      logSelection = selection;
      logFailure = null;
      logPage = page;
      logTotal = result.total;
      $("command-log").append(...result.data.map(logEntry));
      limitations(result.limitations);
      // An explicit refresh reloads up to the previous position so the reader's entry can be restored.
      if (
        restore &&
        !logCards.has(restore.id) &&
        page * 100 < Math.min(result.total, restore.loaded)
      ) {
        page += 1;
        continue;
      }
      if (restore && !restoreLogAnchor(restore))
        $("command-status").textContent =
          "Refreshed; your previous entry no longer matches this search.";
      break;
    }
    logStatus();
  } catch (e) {
    if (token === commandRequest) {
      if (e.stale)
        markLogStale("Analyst content changed since this search ran.");
      else {
        logFailure = { selection, page };
        $("command-status").textContent = e.message;
        $("log-load-status").textContent =
          `Could not load requested activity: ${e.message}. Previously loaded results and drafts are unchanged.`;
        $("more-log").hidden = false;
      }
    }
  } finally {
    if (token === commandRequest) {
      logBusy = false;
      $("more-log").disabled = false;
    }
  }
}

function sheetStatus() {
  const loaded = sheetTable.getDataCount();
  $("sheet-load-status").textContent =
    `${number(loaded)} / ${number(sheetTotal)} rows loaded · ${loaded < sheetTotal ? "Scroll down to load more" : "All matching rows loaded"}`;
  $("more-sheet").hidden = loaded >= sheetTotal;
  $("more-sheet").disabled = sheetBusy;
}

function sheetCell(cell) {
  const row = cell.getRow().getData();
  const value =
    cell.getField() === "requested_ms" && cell.getValue() !== null
      ? shown(cell.getValue()) + " " + meta.timezone
      : cell.getValue();
  $("sheet-cell-title").textContent = cell.getColumn().getDefinition().title;
  $("sheet-cell-context").textContent =
    `${row.command_id} / ${row.region} / ${row.instance_id || "Unknown system"} / ${row.plugin || "No plugin collected"}`;
  $("sheet-cell-value").textContent =
    value === null ? "Not collected" : String(value ?? "");
  $("sheet-copy-status").textContent = "";
  $("copy-sheet-cell").onclick = async () => {
    try {
      await navigator.clipboard.writeText(String(value ?? ""));
      $("sheet-copy-status").textContent = "Copied";
    } catch {
      $("sheet-copy-status").textContent =
        "Clipboard unavailable. Select and copy the text above.";
    }
  };
  $("sheet-cell-command").onclick = () => {
    $("sheet-cell-dialog").close();
    openCommand(row.key);
  };
  $("sheet-cell-dialog").showModal();
}

function createCommandSheet() {
  const column = (title, field, width, extra = {}) => ({
    title,
    field,
    width,
    minWidth: 55,
    headerTooltip: title,
    variableHeight: true,
    formatter: (cell) => {
      const value = cell.getValue();
      const text = document.createElement("div");
      text.className = "sheet-value";
      text.tabIndex = 0;
      text.setAttribute("aria-label", `Inspect ${title}`);
      text.onkeydown = (e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          sheetCell(cell);
        }
      };
      text.textContent = value === null ? "Not collected" : String(value ?? "");
      if (value === null) text.classList.add("sheet-missing");
      if (field === "status" && value === "Failed")
        text.classList.add("sheet-failed");
      return text;
    },
    cellClick: (_e, cell) => sheetCell(cell),
    ...extra,
  });
  sheetTable = new Tabulator("#command-sheet", {
    height: "calc(100vh - 120px)",
    layout: "fitDataStretch",
    index: "row_id",
    placeholder:
      "No matching command outputs. Widen the time range or clear command search.",
    sortMode: "remote",
    initialSort: [{ column: "requested_ms", dir: "desc" }],
    ajaxURL: "/api/ssm-sheet",
    ajaxRequestFunc: async (_url, _config, params) => {
      const token = ++sheetRequest;
      sheetBusy = true;
      sheetPage = 1;
      sheetTotal = 0;
      sheetSelection = { ...commandQuery(), sorters: params.sort };
      $("sheet-load-status").textContent = "Loading rows…";
      $("command-status").textContent = "Loading spreadsheet…";
      $("more-sheet").hidden = true;
      try {
        const result = await request("/api/ssm-sheet", sheetSelection);
        if (token !== sheetRequest) return [];
        sheetTotal = result.total;
        $("command-status").textContent = result.loaded
          ? `${number(result.total)} system/plugin rows across ${number(result.commands)} matching commands`
          : "No SSM export loaded. Start the server with --ssm-export PATH.";
        limitations(result.limitations);
        return result.data;
      } catch (e) {
        if (token === sheetRequest) $("command-status").textContent = e.message;
        throw e;
      } finally {
        if (token === sheetRequest) sheetBusy = false;
      }
    },
    columns: [
      column("System / details", "instance_id", 170, {
        frozen: true,
        formatter: (cell) => {
          const button = document.createElement("button");
          button.className = "sheet-value sheet-open";
          button.textContent = cell.getValue() || "Unknown system";
          button.title = "Open command and CloudTrail links";
          button.onclick = (e) => {
            e.stopPropagation();
            openCommand(cell.getRow().getData().key);
          };
          return button;
        },
        cellClick: () => {},
      }),
      column("Requested (local)", "requested_ms", 150, {
        formatter: (cell) => {
          const text = document.createElement("div");
          text.className = "sheet-value";
          text.tabIndex = 0;
          text.setAttribute("aria-label", "Inspect requested time");
          text.onkeydown = (e) => {
            if (e.key === "Enter" || e.key === " ") {
              e.preventDefault();
              sheetCell(cell);
            }
          };
          text.textContent =
            cell.getValue() === null ? "Unknown time" : shown(cell.getValue());
          return text;
        },
      }),
      column("Plugin", "plugin", 150),
      column("Status", "status", 90),
      column("Code", "response_code", 86),
      column("Command parameters", "parameters", 310),
      column("Stdout", "stdout", 340),
      column("Stderr", "stderr", 240),
      column("Decoded payloads", "decoded", 300),
      column("Combined output (fallback)", "combined_output", 240),
      column("Output coverage", "output_state", 150),
      column("CloudTrail links", "events", 90),
      column("Command ID", "command_id", 290),
      column("Region", "region", 130),
      column("Account", "account", 130),
      column("Document", "document", 210),
    ],
  });
  sheetTable.on("dataProcessed", sheetStatus);
  sheetTable.on("scrollVertical", (top) => {
    const holder = document.querySelector(
      "#command-sheet .tabulator-tableholder",
    );
    if (holder.scrollHeight - holder.clientHeight - top < 150) loadMoreSheet();
  });
}

function limitations(items) {
  $("command-limitations").replaceChildren(
    ...items.map((text) => {
      const li = document.createElement("li");
      li.textContent = text;
      return li;
    }),
  );
}

async function loadMoreSheet() {
  if (sheetBusy || !commandSheet || sheetTable.getDataCount() >= sheetTotal)
    return;
  const token = sheetRequest;
  sheetBusy = true;
  sheetStatus();
  try {
    const result = await request("/api/ssm-sheet", {
      ...sheetSelection,
      page: sheetPage + 1,
    });
    if (token !== sheetRequest) return;
    await sheetTable.addData(result.data);
    sheetPage++;
  } catch (e) {
    if (token === sheetRequest) $("command-status").textContent = e.message;
  } finally {
    if (token === sheetRequest) {
      sheetBusy = false;
      sheetStatus();
    }
  }
}

function evidenceText(parent, title, value) {
  const heading = document.createElement("h3");
  heading.textContent = title;
  const pre = document.createElement("pre");
  pre.textContent =
    typeof value === "string" ? value : JSON.stringify(value, null, 2);
  parent.append(heading, pre);
}

function switchView(commands, run = true) {
  if (commandsActive && commandLog && !commands) leaveLog();
  commandsActive = commands;
  syncLogEditor();
  $("commands-panel").hidden = !commands;
  $("events-tab").setAttribute("aria-pressed", String(!commands));
  $("commands-tab").setAttribute("aria-pressed", String(commands));
  for (const id of ["frequency-block", "query-bar", "sql-panel"])
    $(id).hidden = commands;
  document.querySelector(".results").hidden = commands;
  if (!run) return;
  if (commands) loadCommands();
  else {
    table.redraw(true);
    fitGrid();
    reload();
  }
}

async function loadCommands(more = false) {
  if (commandLog) return loadLog({ more });
  if (commandSheet) {
    if (!sheetTable) createCommandSheet();
    else {
      sheetTable.redraw(true);
      sheetTable.setData().catch(() => {});
    }
    return;
  }
  const token = ++commandRequest;
  const page = more ? commandPage + 1 : 1;
  $("command-status").textContent = "Loading commands…";
  $("more-commands").disabled = true;
  try {
    const result = await request("/api/ssm", {
      ...commandQuery(),
      sort: $("command-sort").value,
      direction: $("command-direction").value,
      page,
    });
    if (token !== commandRequest) return;
    commandPage = page;
    if (!more) $("command-list").replaceChildren();
    $("command-status").textContent = result.loaded
      ? `${number(result.total)} commands matching requested time and search · ${Math.min(page * 100, result.total)} loaded`
      : "No SSM export loaded. Start the server with --ssm-export PATH to a local command/session activity JSON export.";
    $("more-commands").hidden = page * 100 >= result.total;
    limitations(result.limitations);
    for (const row of result.data) {
      const button = document.createElement("button");
      button.className = "command-entry";
      button.dataset.key = row.key;
      button.setAttribute("aria-pressed", String(commandKey === row.key));
      const title = document.createElement("strong");
      title.textContent = `${row.requested_ms === null ? "Unknown time" : shown(row.requested_ms)} ${meta.timezone} · ${row.status}`;
      const id = document.createElement("code");
      id.textContent = row.command_id;
      const info = document.createElement("span");
      info.textContent = `${row.document} · ${row.region} · ${row.systems} known systems / ${row.target_count ?? "unknown"} targets reported · ${row.events} events${row.decoded ? " · decoded payload" : ""}`;
      button.append(title, id, info);
      button.onclick = () => openCommand(row.key);
      $("command-list").append(button);
    }
  } catch (e) {
    if (token === commandRequest) $("command-status").textContent = e.message;
  } finally {
    if (token === commandRequest) $("more-commands").disabled = false;
  }
}

async function openCommand(key, keepLayout = false) {
  if ((commandSheet || commandLog) && !keepLayout) commandLayout(false);
  const token = ++commandDetailRequest;
  try {
    const command = await request("/api/ssm-detail", { key });
    if (token !== commandDetailRequest) return;
    commandKey = key;
    document
      .querySelectorAll(".command-entry")
      .forEach((b) =>
        b.setAttribute("aria-pressed", String(b.dataset.key === key)),
      );
    const view = $("command-view");
    view.replaceChildren();
    const heading = document.createElement("h2");
    heading.textContent = `${command.document} · ${command.status}`;
    const description = document.createElement("p");
    description.className = "hint";
    description.textContent = `${command.account} / ${command.region} / ${command.command_id}\n${command.systems.length} known systems; ${command.target_count ?? "unknown"} targets reported by SSM. Missing output is not proof the command did not run.`;
    const jump = document.createElement("button");
    jump.textContent = `Show ${command.events.filter((e) => e.id !== null).length} linked events in CloudTrail grid`;
    jump.onclick = () => showCommandEvents(key, command.command_id);
    view.append(heading, description, jump);
    evidenceText(
      view,
      "Command parameters (original)",
      command.record?.Parameters || "Command parameters were not collected.",
    );
    if (command.record?.Comment)
      evidenceText(view, "Comment", command.record.Comment);
    if (command.record?.Targets?.length)
      evidenceText(view, "Target selectors", command.record.Targets);
    const decoded = (items, parent, depth = 0) => {
      for (const item of items) {
        evidenceText(
          parent,
          `Decoded payload · layer ${depth + 1} · ${item.status} · ${item.kind}`,
          item.decoded_text ??
            item.error ??
            "Non-UTF-8 bytes; see raw enrichment below.",
        );
        decoded(item.nested_decodings || [], parent, depth + 1);
      }
    };
    for (const parameter of command.base64_enrichment) {
      const section = document.createElement("section");
      section.className = "command-enrichment";
      const caption = document.createElement("h3");
      caption.textContent = `Static base64 enrichment: ${parameter.parameter}[${parameter.value_index}] (decoded as data, never executed)`;
      section.append(caption);
      decoded(parameter.decodings, section);
      view.append(section);
    }
    const systemTitle = document.createElement("h3");
    systemTitle.textContent = "Per-system execution and output";
    view.append(systemTitle);
    for (const system of command.systems) {
      const section = document.createElement("details");
      section.className = "system-result";
      section.open = true;
      const summary = document.createElement("summary");
      summary.textContent = `${system.instance_id} ${system.invocation?.InstanceName || ""} · ${system.invocation?.Status || system.details[0]?.Status || "No invocation collected"}`;
      section.append(summary);
      const plugins = new Map(
        (system.invocation?.CommandPlugins || []).map((p) => [
          p.Name,
          { plugin: p, details: [] },
        ]),
      );
      for (const detail of system.details) {
        if (!plugins.has(detail.PluginName))
          plugins.set(detail.PluginName, { plugin: null, details: [] });
        plugins.get(detail.PluginName).details.push(detail);
      }
      if (!plugins.size)
        evidenceText(
          section,
          "Output",
          "No plugin output was collected for this system.",
        );
      for (const [name, plugin] of plugins) {
        if (!plugin.details.length) {
          evidenceText(
            section,
            `${name} · ${plugin.plugin.Status} · response ${plugin.plugin.ResponseCode ?? "unknown"}`,
            plugin.plugin.Output || "No combined plugin output returned.",
          );
          for (const field of ["StandardOutputUrl", "StandardErrorUrl"])
            if (plugin.plugin[field])
              evidenceText(
                section,
                field + " (not fetched)",
                plugin.plugin[field],
              );
        }
        for (const detail of plugin.details) {
          evidenceText(
            section,
            `${name} · ${detail.Status} · response ${detail.ResponseCode ?? "unknown"}`,
            `Start: ${displayTime(detail.ExecutionStartDateTime)}\nEnd: ${displayTime(detail.ExecutionEndDateTime)}`,
          );
          evidenceText(
            section,
            "Standard output",
            detail.StandardOutputContent ?? "Not collected",
          );
          evidenceText(
            section,
            "Standard error",
            detail.StandardErrorContent ?? "Not collected",
          );
          for (const field of ["StandardOutputUrl", "StandardErrorUrl"])
            if (detail[field])
              evidenceText(section, field + " (not fetched)", detail[field]);
        }
      }
      view.append(section);
    }
    const links = document.createElement("section");
    links.className = "command-events";
    const title = document.createElement("h3");
    title.textContent = `${command.events.length} linked CloudTrail events (exact command ID, account and region)`;
    links.append(title);
    const show = document.createElement("button");
    show.textContent = "Show linked events in CloudTrail grid";
    show.onclick = () => showCommandEvents(key, command.command_id);
    links.append(show);
    const notice = document.createElement("p");
    notice.className = "hint";
    notice.textContent =
      "The grid contains only the original DuckDB evidence. Supplemental-only events can be opened below; they are not silently added to that evidence. Back returns to your previous CloudTrail query.";
    links.append(notice);
    for (const event of command.events) {
      const button = document.createElement("button");
      button.className = "linked-event";
      button.textContent = `${shown(Date.parse(event.event_time))} ${meta.timezone} · ${event.operation} · ${event.error || "No API error"}\n${event.identity} · ${event.source_ip}\n${event.event_id} · ${event.source}`;
      button.onclick = async () => {
        if (event.id !== null) await detail({ id: event.id });
        else {
          try {
            const data = await request("/api/ssm-event", { key: event.key });
            detailRow = null;
            $("detail-id").textContent =
              `${data.event_id} · Supplemental SSM export (not in original DuckDB)`;
            $("raw-event").textContent = data.raw_json;
            $("record-hash").textContent =
              "Supplemental event reconstructed from export JSON; original evidence database is unchanged.";
            $("detail-findings").replaceChildren();
            $("detail-prev").hidden = $("detail-next").hidden = true;
            eventCommandLinks([{ key, command_id: command.command_id }]);
            openDetail();
          } catch (e) {
            error(e.message);
          }
        }
      };
      links.append(button);
    }
    view.append(links);
    const raw = document.createElement("details");
    const summary = document.createElement("summary");
    summary.textContent = "Raw command, invocation and enrichment records";
    raw.append(summary);
    evidenceText(raw, "Collected records", {
      record: command.record,
      systems: command.systems,
      base64_enrichment: command.base64_enrichment,
    });
    view.append(raw);
  } catch (e) {
    if (token === commandDetailRequest) error(e.message);
  }
}

// Isolated pivot: the whole export, only this command's exact links. Back restores the previous query.
function showCommandEvents(key, label) {
  switchView(false, false);
  apply({
    start: meta.start_ms,
    end: meta.end_ms,
    command_key: key,
    command_label: label,
  });
}

function eventCommandLinks(commands) {
  $("event-command-links").replaceChildren();
  for (const command of commands) {
    const button = document.createElement("button");
    button.textContent = `Open SSM command ${command.command_id}`;
    button.onclick = () => {
      $("detail").close();
      switchView(true);
      openCommand(command.key);
      $("commands-panel").scrollIntoView();
    };
    $("event-command-links").append(button);
  }
}

// ---- Selection, tags and notes ---------------------------------------------------------------
function selectionStatus() {
  const n = selectedEvents.size;
  $("selected-count").textContent = `${number(n)} selected`;
  $("quick-tag").disabled = $("add-to-note").disabled = !n;
  const header = document.querySelector(
    '[aria-label="Select all loaded events"]',
  );
  const loaded = table?.getData() || [];
  if (header) {
    const count = loaded.filter((r) =>
      selectedEvents.has(r.record_sha256),
    ).length;
    header.checked = loaded.length > 0 && count === loaded.length;
    header.indeterminate = count > 0 && count < loaded.length;
  }
  renderNotes();
}

function markdown(target, text) {
  target.innerHTML = DOMPurify.sanitize(marked.parse(text), {
    ALLOWED_TAGS: [
      "p",
      "br",
      "strong",
      "em",
      "del",
      "a",
      "code",
      "pre",
      "blockquote",
      "ul",
      "ol",
      "li",
      "h1",
      "h2",
      "h3",
      "h4",
      "h5",
      "h6",
      "hr",
      "table",
      "thead",
      "tbody",
      "tr",
      "th",
      "td",
    ],
    ALLOWED_ATTR: ["href", "title", "start"],
  });
}

async function refreshReviews() {
  reviews = await request("/api/reviews");
  noteEvents.clear();
  tabLabel("tags-tab", "Event tags", reviews.tags.length);
  tabLabel("notes-tab", "Findings", reviews.annotations.length);
  renderTags();
  renderNotes();
  if (applied) renderScopes();
}

const textColor = (hex) => {
  const [r, g, b] = [1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16));
  return 0.299 * r + 0.587 * g + 0.114 * b > 150 ? "#14232e" : "#fff";
};

function swatch(tag, onClick) {
  const s = document.createElement(onClick ? "button" : "span");
  s.className = "tag-square";
  s.style.backgroundColor = tag.color;
  s.style.color = textColor(tag.color);
  s.textContent = tag.slug[0].toUpperCase();
  s.title = tag.slug;
  if (onClick) {
    s.type = "button";
    s.onclick = onClick;
  }
  return s;
}

function toggleTagFilter(slug) {
  if (commandsActive) switchView(false, false);
  apply({
    ...applied,
    tags: applied.tags.includes(slug)
      ? applied.tags.filter((t) => t !== slug)
      : [...applied.tags, slug],
  });
}

function renderTags() {
  if (!applied) return;
  const term = $("tag-search").value.trim().toLowerCase();
  const items = reviews.tags
    .filter((t) => t.slug.includes(term))
    .map((tag) => {
      const li = document.createElement("li");
      li.className =
        "tag-item" + (applied.tags.includes(tag.slug) ? " active" : "");
      const color = swatch(tag, (e) => {
        e.stopPropagation();
        $("recolor").dataset.slug = tag.slug;
        $("recolor").value = tag.color;
        $("recolor").click();
      });
      color.title = `Recolor ${tag.slug} everywhere`;
      color.setAttribute("aria-label", `Recolor tag ${tag.slug}`);
      const name = document.createElement("button");
      name.type = "button";
      name.className = "tag-name";
      name.textContent = tag.slug;
      name.title = applied.tags.includes(tag.slug)
        ? "Remove this tag filter"
        : "Filter to events with this tag (added to the current query)";
      name.onclick = () => toggleTagFilter(tag.slug);
      const count = document.createElement("span");
      count.className = "count";
      count.textContent = number(tag.events);
      li.append(color, name, count);
      return li;
    });
  if (!items.length) {
    const li = document.createElement("li");
    li.className = "hint";
    li.textContent = reviews.tags.length
      ? "No matching tags."
      : "No tags yet. Select events and use Tag events.";
    items.push(li);
  }
  $("tag-list").replaceChildren(...items);
  renderRail();
}

// The collapsed rail: every tag as a compact filter toggle; full names show on hover/focus.
function renderRail() {
  // Rebuilt buttons never fire blur/pointerleave: drop the tip and keep keyboard focus in place.
  $("rail-tip").hidden = true;
  const focused = document.activeElement?.closest?.(".rail-tag")?.dataset.slug;
  const items = reviews.tags.map((tag) => {
    const li = document.createElement("li");
    const active = applied.tags.includes(tag.slug);
    const b = document.createElement("button");
    b.type = "button";
    b.className = "rail-tag" + (active ? " active" : "");
    b.dataset.slug = tag.slug;
    b.setAttribute("aria-pressed", String(active));
    b.setAttribute("aria-describedby", "rail-tip");
    const color = swatch(tag);
    color.removeAttribute("title");
    if (active) color.textContent = "✓";
    color.setAttribute("aria-hidden", "true");
    const name = document.createElement("span");
    name.className = "rail-name";
    name.textContent = tag.slug;
    b.append(color, name);
    const tip = () => {
      $("rail-tip").textContent =
        `${tag.slug} · ${number(tag.events)} events · ` +
        (active ? "filter on; click to remove" : "click to filter");
      $("rail-tip").hidden = false;
      const r = b.getBoundingClientRect();
      $("rail-tip").style.left = `${r.right + 6}px`;
      $("rail-tip").style.top = `${r.top + r.height / 2}px`;
    };
    const untip = () => ($("rail-tip").hidden = true);
    b.onpointerenter = tip;
    b.onfocus = () => b.matches(":focus-visible") && tip();
    b.onpointerleave = b.onblur = untip;
    b.onclick = () => {
      untip();
      toggleTagFilter(tag.slug);
    };
    li.append(b);
    return li;
  });
  if (!items.length) {
    const li = document.createElement("li");
    li.className = "hint";
    li.textContent = "No tags yet";
    items.push(li);
  }
  $("rail-tags").replaceChildren(...items);
  if (focused)
    $("rail-tags").querySelector(`[data-slug="${focused}"]`)?.focus();
}

function showNotes(ids) {
  setSidebar(true);
  sidebarTab("notes");
  noteScope = ids;
  expandedNotes = new Set(ids);
  renderNotes();
}

async function linkedEvents(note, target) {
  target.textContent = "Loading linked events…";
  try {
    if (!noteEvents.has(note.id))
      noteEvents.set(
        note.id,
        await request("/api/events", {
          timezone: meta.timezone,
          annotation_id: note.id,
          size: 25,
          sorters: [{ field: "time_local", dir: "asc" }],
        }),
      );
    const result = noteEvents.get(note.id);
    const list = document.createElement("ol");
    list.className = "linked-list";
    for (const row of result.data) {
      const li = document.createElement("li");
      const button = document.createElement("button");
      button.type = "button";
      button.textContent = `${row.time_local} · ${row.event_name}`;
      button.title = `${row.event_id} · ${row.identity}`;
      button.onclick = () => detail(row);
      li.append(button);
      list.append(li);
    }
    const caption = document.createElement("p");
    caption.className = "hint";
    caption.textContent =
      result.last_row > result.data.length
        ? `First ${result.data.length} of ${number(result.last_row)} linked events (oldest first)`
        : `${number(result.last_row)} linked events (oldest first)`;
    target.replaceChildren(caption, list);
  } catch (e) {
    target.textContent = e.message;
  }
}

function renderNotes() {
  if (!applied) return;
  const term = $("note-search").value.trim().toLowerCase();
  $("note-scope").hidden = !noteScope;
  if (noteScope) {
    $("note-scope").replaceChildren(
      `Showing ${noteScope.length} finding(s) on one event · `,
    );
    const all = document.createElement("button");
    all.className = "text-button";
    all.textContent = "Show all findings";
    all.onclick = () => {
      noteScope = null;
      renderNotes();
    };
    $("note-scope").append(all);
  }
  const selected = [...selectedEvents];
  const items = reviews.annotations
    .filter((n) => !noteScope || noteScope.includes(n.id))
    .filter(
      (n) =>
        !term || n.body.toLowerCase().includes(term) || `#${n.id}` === term,
    )
    .map((note) => {
      const li = document.createElement("li");
      li.className =
        "note-card" + (applied.annotation_id === note.id ? " active" : "");
      const head = document.createElement("button");
      head.type = "button";
      head.className = "note-head";
      head.setAttribute("aria-expanded", String(expandedNotes.has(note.id)));
      const title = document.createElement("strong");
      title.textContent = noteTitle(note);
      const info = document.createElement("span");
      info.className = "hint";
      info.textContent = `#${note.id} · ${number(note.events)} linked events · ${shown(Date.parse(note.updated)).slice(0, 16)} ${meta.timezone}`;
      head.append(title, info);
      head.onclick = () => {
        if (expandedNotes.has(note.id)) expandedNotes.delete(note.id);
        else expandedNotes.add(note.id);
        renderNotes();
      };
      li.append(head);
      if (expandedNotes.has(note.id)) {
        const body = document.createElement("div");
        body.className = "markdown";
        // The card heading already shows the first line; render the rest.
        markdown(body, note.body.replace(/^\s*[^\n]*\n?/, ""));
        const actions = document.createElement("div");
        actions.className = "note-actions";
        const action = (label, handler, title) => {
          const b = document.createElement("button");
          b.type = "button";
          b.textContent = label;
          if (title) b.title = title;
          b.onclick = handler;
          actions.append(b);
        };
        action(
          "Filter to finding",
          () => {
            if (commandsActive) switchView(false, false);
            apply({ ...applied, annotation_id: note.id });
          },
          "Add this finding's events to the current query (AND)",
        );
        action(
          "All linked",
          () => {
            if (commandsActive) switchView(false, false);
            apply({
              start: meta.start_ms,
              end: meta.end_ms,
              annotation_id: note.id,
            });
          },
          "Whole export, only this finding's events. Back restores your query.",
        );
        if (note.context)
          action(
            "Reopen query",
            () => {
              if (commandsActive) switchView(false, false);
              apply(note.context);
            },
            "Restore the query this finding was written from",
          );
        const rows = rowsByHash();
        const onNote = selected.filter((h) =>
          rows.get(h)?.annotations.includes(note.id),
        );
        const unlinked = selected.filter((h) => !onNote.includes(h));
        if (unlinked.length)
          action(
            `Link ${unlinked.length} selected`,
            () =>
              writeReview({ action: "link", id: note.id, hashes: unlinked }),
            "Link the selected events that are not yet linked to this finding",
          );
        if (onNote.length)
          action(
            `Unlink ${onNote.length} selected`,
            () =>
              writeReview({ action: "unlink", id: note.id, hashes: onNote }),
            "Unlink the selected events from this finding",
          );
        action("Edit", () => noteDialog(note));
        action("Delete", () => {
          if (
            confirm(
              `Delete finding #${note.id} and its links to ${note.events} events? Event tags are unaffected.`,
            )
          )
            writeReview({
              action: "delete",
              id: note.id,
              updated: note.updated,
            });
        });
        const linked = document.createElement("div");
        linked.className = "linked";
        li.append(body, actions, linked);
        linkedEvents(note, linked);
      }
      return li;
    });
  if (!items.length) {
    const li = document.createElement("li");
    li.className = "hint";
    li.textContent = reviews.annotations.length
      ? "No matching findings."
      : "No findings yet. Select events and use Add to finding.";
    items.push(li);
  }
  $("note-list").replaceChildren(...items);
}

// Collapsed, the sidebar is a narrow tag rail that stays visible; expanded, the full panel.
function setSidebar(open) {
  document.querySelector(".layout").classList.toggle("sidebar-open", open);
  $("rail").hidden = open;
  $("sidebar-panel").hidden = !open;
  $("rail-tip").hidden = true;
  localStorage.setItem("sidebar-expanded", open ? "1" : "0");
  requestAnimationFrame(() => {
    table?.redraw();
    if (lastHistogram) frequency(lastHistogram, lastContext);
    timeline();
    paintSelection();
  });
}

function tabLabel(id, label, n) {
  const count = document.createElement("span");
  count.className = "tab-count";
  count.textContent = number(n);
  $(id).replaceChildren(label, count);
}

function sidebarTab(which) {
  for (const name of ["tags", "notes", "detections"]) {
    $(`${name}-tab`).setAttribute("aria-selected", String(which === name));
    $(`${name}-pane`).hidden = which !== name;
  }
}

// ---- Suzaku (Sigma) detections: read-only, imported by `kamotrace suzaku` --------------------
let detections = { run: null, rules: [] };

function levelBadge(level) {
  const b = document.createElement("span");
  b.className = "level level-" + level;
  b.textContent =
    { informational: "I", low: "L", medium: "M", high: "H", critical: "C" }[
      level
    ] || "?";
  b.title = level;
  return b;
}

function toggleRuleFilter(id) {
  if (commandsActive) switchView(false, false);
  apply({
    ...applied,
    rules: applied.rules.includes(id)
      ? applied.rules.filter((r) => r !== id)
      : [...applied.rules, id],
  });
}

function renderDetections() {
  if (!applied) return;
  const term = $("rule-search").value.trim().toLowerCase();
  const items = detections.rules
    .filter(
      (r) =>
        !term ||
        [r.title, r.level, ...r.tactics, ...r.techniques]
          .join(" ")
          .toLowerCase()
          .includes(term),
    )
    .map((rule) => {
      const li = document.createElement("li");
      li.className =
        "tag-item" + (applied.rules.includes(rule.rule_id) ? " active" : "");
      const name = document.createElement("button");
      name.type = "button";
      name.className = "tag-name";
      name.textContent = rule.title;
      name.title =
        `${rule.level} · ${[...rule.tactics, ...rule.techniques].join(", ") || "no ATT&CK tags"}\n` +
        `Rule ${rule.rule_id}\n` +
        (applied.rules.includes(rule.rule_id)
          ? "Remove this rule filter"
          : "Filter to events this rule matched (added to the current query)");
      name.onclick = () => toggleRuleFilter(rule.rule_id);
      const count = document.createElement("span");
      count.className = "count";
      count.textContent = number(rule.events);
      li.append(levelBadge(rule.level), name, count);
      return li;
    });
  if (!items.length) {
    const li = document.createElement("li");
    li.className = "hint";
    li.textContent = detections.rules.length
      ? "No matching rules."
      : "No detections linked to this evidence.";
    items.push(li);
  }
  $("rule-list").replaceChildren(...items);
  const run = detections.run;
  $("detections-run").textContent = run
    ? `Suzaku ${run.suzaku_version} · ${number(run.suzaku_rules_count ?? 0)} rules loaded · ` +
      `${number(run.linked_rows)} matches linked` +
      (run.no_match_rows || run.ambiguous_rows
        ? ` · ${number(run.no_match_rows + run.ambiguous_rows)} not linked (no exact event)`
        : "") +
      ". Detections are automated leads: tag events or record a finding about what you observe."
    : "";
}

async function loadDetections() {
  detections = await request("/api/detections");
  $("detections-tab").hidden = !detections.run;
  tabLabel("detections-tab", "Detections", detections.rules.length);
  renderDetections();
}

function detectionCell(cell) {
  const list = cell.getRow().getData().detections || [];
  if (!list.length) return "";
  const b = document.createElement("button");
  b.type = "button";
  b.className = "detection-marker";
  b.append(levelBadge(list[0].level));
  if (list.length > 1) b.append(String(list.length));
  b.title = list.map((d) => `[${d.level}] ${d.title}`).join("\n");
  b.setAttribute("aria-label", `${list.length} Suzaku detections; show them`);
  b.onclick = (e) => {
    e.stopPropagation();
    const menu = $("tag-popover");
    const title = document.createElement("p");
    title.className = "menu-title";
    title.textContent = `Suzaku detections on this event (${list.length})`;
    const ul = document.createElement("ul");
    for (const d of list) {
      const li = document.createElement("li");
      const r = document.createElement("button");
      r.type = "button";
      r.className = "full-tag";
      r.title = "Filter to events this rule matched";
      r.append(levelBadge(d.level), d.title);
      r.onclick = () => {
        menu.hidePopover();
        toggleRuleFilter(d.rule_id);
      };
      li.append(r);
      ul.append(li);
    }
    menu.replaceChildren(title, ul);
    placeMenu(menu, b);
  };
  return b;
}

function placeMenu(menu, anchor) {
  if (!menu.matches(":popover-open")) menu.showPopover();
  const rect = anchor.getBoundingClientRect();
  menu.style.left =
    Math.max(8, Math.min(rect.left, innerWidth - menu.offsetWidth - 8)) + "px";
  menu.style.top =
    Math.max(
      8,
      Math.min(rect.bottom + 4, innerHeight - menu.offsetHeight - 8),
    ) + "px";
}

function rowsByHash() {
  const map = new Map();
  for (const row of table.getData()) map.set(row.record_sha256, row);
  if (detailRow) map.set(detailRow.record_sha256, detailRow);
  for (const { row } of logCards.values())
    for (const e of row.events)
      if (e.record_sha256 && !map.has(e.record_sha256))
        map.set(e.record_sha256, {
          record_sha256: e.record_sha256,
          tags: e.tags,
          annotations: e.findings.map((f) => f.id),
        });
  return map;
}

function openQuickTag(anchor, hashes) {
  quickTagHashes = hashes;
  $("tag-slug").value = "";
  $("quick-tag-error").textContent = "";
  renderQuickTag();
  placeMenu($("quick-tag-menu"), anchor);
  $("tag-slug").focus();
}

function renderQuickTag() {
  const rows = rowsByHash();
  const n = quickTagHashes.length;
  $("quick-tag-title").textContent =
    n === 1 ? "Tags on this event" : `Tags on ${number(n)} selected events`;
  const term = $("tag-slug").value.trim().toLowerCase();
  const counts = new Map(
    reviews.tags.map((t) => [
      t.slug,
      quickTagHashes.filter((h) =>
        rows.get(h)?.tags.some((x) => x.slug === t.slug),
      ).length,
    ]),
  );
  const tags = reviews.tags
    .filter((t) => t.slug.includes(term))
    .sort(
      (a, b) =>
        (counts.get(b.slug) > 0) - (counts.get(a.slug) > 0) ||
        a.slug.localeCompare(b.slug),
    );
  $("quick-tag-list").replaceChildren(
    ...tags.map((tag) => {
      const count = counts.get(tag.slug);
      const li = document.createElement("li");
      const label = document.createElement("label");
      const box = document.createElement("input");
      box.type = "checkbox";
      box.checked = count === n;
      box.indeterminate = count > 0 && count < n;
      box.setAttribute(
        "aria-label",
        `${tag.slug}: ${count === n ? "on all" : count ? "on some" : "on none"}; ${count === n ? "remove from" : "add to"} all ${n}`,
      );
      box.onchange = () =>
        writeReview({
          action: count === n ? "untag" : "tag",
          hashes: quickTagHashes,
          slug: tag.slug,
          color: tag.color,
        });
      const state = document.createElement("span");
      state.className = "count";
      state.textContent = n > 1 ? `${count}/${n}` : "";
      label.append(box, swatch(tag), tag.slug, state);
      li.append(label);
      return li;
    }),
  );
  const exact = reviews.tags.some((t) => t.slug === term);
  $("create-tag").hidden = !term || exact;
  $("tag-color").hidden = !term || exact;
}

async function createTag() {
  const slug = $("tag-slug").value.trim();
  const existing = reviews.tags.find((t) => t.slug === slug);
  await writeReview({
    action: "tag",
    hashes: quickTagHashes,
    slug,
    color: existing?.color || $("tag-color").value,
  });
  $("tag-slug").value = "";
  renderQuickTag();
}

function openNoteMenu(anchor, hashes = [...selectedEvents]) {
  noteMenuHashes = hashes;
  $("note-menu-title").textContent =
    hashes.length === 1
      ? "Add this event to a finding"
      : `Add ${number(hashes.length)} selected events to a finding`;
  $("note-menu-search").value = "";
  renderNoteMenu();
  placeMenu($("note-menu"), anchor);
}

function renderNoteMenu() {
  const term = $("note-menu-search").value.trim().toLowerCase();
  $("note-menu-list").replaceChildren(
    ...reviews.annotations
      .filter((n) => !term || n.body.toLowerCase().includes(term))
      .slice(0, 30)
      .map((note) => {
        const li = document.createElement("li");
        const b = document.createElement("button");
        b.type = "button";
        b.textContent = `#${note.id} ${noteTitle(note)} (${number(note.events)})`;
        b.title = "Link these events to this finding";
        b.onclick = async () => {
          $("note-menu").hidePopover();
          await writeReview({
            action: "link",
            id: note.id,
            hashes: noteMenuHashes,
          });
          showNotes([note.id]);
          noteScope = null;
          renderNotes();
        };
        li.append(b);
        return li;
      }),
  );
}

function scopeSummary(s) {
  const parts = [`${shown(s.start)} → ${shown(s.end)}`];
  if (s.search) parts.push(`search “${s.search}”`);
  for (const f of s.filters)
    parts.push(`${meta.fields[f.field]} ${OPS[f.op][1]} ${f.value}`);
  for (const t of s.tags) parts.push(`tag ${t}`);
  if (s.annotation_id !== null) parts.push(`finding #${s.annotation_id}`);
  for (const r of s.rules || [])
    parts.push(
      `Sigma ${detections.rules.find((d) => d.rule_id === r)?.title || r}`,
    );
  if (s.min_level) parts.push(`Sigma ≥ ${s.min_level}`);
  if (s.command_key !== null)
    parts.push(`SSM command ${s.command_label || ""}`);
  return parts.join(" · ");
}

function noteDialog(note = null, hashes = [...selectedEvents]) {
  editingNote = note; // Keeps `updated`: the server rejects edits to a note changed since.
  reviewHashes = [...hashes];
  $("review-error").hidden = true;
  $("review-title").textContent = note
    ? `Edit finding #${note.id} (${note.events} linked events)`
    : `New finding on ${number(reviewHashes.length)} ${reviewHashes.length === 1 ? "event" : "selected events"}`;
  $("review-context").textContent = note
    ? note.context
      ? "Written from: " + scopeSummary(normalize(note.context))
      : ""
    : "Records the current query so you can reopen it later: " +
      scopeSummary(applied);
  $("note-body").value = note?.body || "";
  markdown($("note-preview"), $("note-body").value);
  $("review-dialog").showModal();
  $("note-body").focus();
}

// Write a review change, then patch loaded rows in place: no grid reload, so scroll position,
// loaded batches and selection survive. Filtered results can go stale; say so instead.
async function writeReview(body) {
  try {
    const result = await request("/api/reviews", body);
    await refreshReviews();
    patchLogEvents(body, result);
    const hashes = new Set(body.hashes || []);
    const tag = reviews.tags.find((t) => t.slug === body.slug);
    const id = body.action === "annotate" ? result.id : body.id;
    const patch = (row) => {
      let tags = row.tags,
        notes = row.annotations;
      const hit = hashes.has(row.record_sha256);
      if (
        body.action === "tag" &&
        hit &&
        !tags.some((t) => t.slug === body.slug)
      )
        tags = [...tags, { slug: body.slug, color: tag.color }].sort((a, b) =>
          a.slug.localeCompare(b.slug),
        );
      if (body.action === "untag" && hit)
        tags = tags.filter((t) => t.slug !== body.slug);
      if (
        tag &&
        tags.some((t) => t.slug === body.slug && t.color !== tag.color)
      )
        tags = tags.map((t) =>
          t.slug === body.slug ? { ...t, color: tag.color } : t,
        );
      if (
        ["annotate", "link"].includes(body.action) &&
        hit &&
        !notes.includes(id)
      )
        notes = [...notes, id];
      if ((body.action === "unlink" && hit) || body.action === "delete")
        notes = notes.filter((n) => n !== id);
      return tags === row.tags && notes === row.annotations
        ? null
        : { tags, annotations: notes };
    };
    for (const row of table.getRows()) {
      const change = patch(row.getData());
      if (change) row.update(change);
    }
    if (detailRow) {
      const change = patch(detailRow);
      if (change) Object.assign(detailRow, change);
      detailFindings();
    }
    const tagFiltered =
      ["tag", "untag"].includes(body.action) &&
      applied.tags.includes(body.slug);
    const noteFiltered =
      ["link", "unlink", "delete"].includes(body.action) &&
      applied.annotation_id === id;
    if (tagFiltered || noteFiltered) $("stale").hidden = false;
    if ($("quick-tag-menu").matches(":popover-open")) renderQuickTag();
    return result;
  } catch (e) {
    if ($("quick-tag-menu").matches(":popover-open"))
      $("quick-tag-error").textContent = e.message;
    else error(e.message);
  }
}

const error = (message) => {
  $("error").textContent = message;
  $("error").hidden = !message;
};

async function request(url, body) {
  const res = await fetch(
    url,
    body === undefined
      ? {}
      : {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(body),
        },
  );
  const result = await res.json();
  if (!res.ok)
    throw Object.assign(new Error(result.error || `HTTP ${res.status}`), {
      stale: result.stale === true,
    });
  return result;
}

function range(start, end) {
  if (!Number.isFinite(start) || !Number.isFinite(end) || start >= end) {
    error("Choose a valid time range: start must be before the exclusive end.");
    return;
  }
  apply({ ...applied, start, end });
}

function paintSelection() {
  const start = parseInput($("start").value),
    end = parseInput($("end").value);
  const hours = (end - start) / 3600000;
  $("range-duration").textContent = !Number.isFinite(hours)
    ? "Invalid time"
    : hours >= 48
      ? `${(hours / 24).toFixed(1)} days`
      : `${hours.toFixed(1)} hours`;
  document.querySelectorAll("#timeline .bar").forEach((bar) => {
    const ms = Number(bar.dataset.ms);
    bar.style.opacity =
      Number(bar.dataset.endMs) > start && ms < end ? "1" : ".22";
  });
}

function reload() {
  if (commandsActive) {
    paintSelection();
    loadCommands();
    return;
  }
  error("");
  $("stale").hidden = true;
  table.setData().catch((e) => error(e.message));
}

async function loadMore() {
  if (
    loadingFirst ||
    loadingMore ||
    !lastResult ||
    table.getDataCount() >= lastResult.last_row
  )
    return;
  const requestId = latestQuery;
  loadingMore = true;
  $("load-status").textContent = "Loading more…";
  try {
    const result = await request("/api/events", {
      ...lastSelection,
      page: nextPage,
      size: 100,
      sorters: table.getSorters().map(({ field, dir }) => ({ field, dir })),
    });
    // Discard superseded batches before they can enter the grid.
    if (requestId !== latestQuery) return;
    nextPage++;
    await table.addData(result.data);
    loadStatus();
    selectionStatus();
  } catch (e) {
    if (requestId === latestQuery) {
      error(e.message);
      $("load-status").textContent =
        "Could not load more. Scroll up and down to retry.";
    }
  } finally {
    if (requestId === latestQuery) loadingMore = false;
  }
}

function loadStatus() {
  const loaded = table.getDataCount();
  $("load-status").textContent =
    `${number(loaded)} loaded${loaded >= (lastResult?.last_row || 0) ? " · all" : " · scroll for more"}`;
}

// ---- Event inspector (non-modal side panel) -------------------------------------------------
function openDetail() {
  if (!$("detail").open) $("detail").show();
}

function detailFindings() {
  const target = $("detail-findings");
  target.replaceChildren();
  if (!detailRow) return;
  const tags = document.createElement("div");
  tags.className = "detail-tags";
  const label = document.createElement("strong");
  label.textContent = "Tags";
  tags.append(label);
  for (const tag of detailRow.tags) {
    const b = document.createElement("button");
    b.type = "button";
    b.className = "full-tag";
    b.title = "Filter to this tag";
    b.append(swatch(tag), tag.slug);
    b.onclick = () => toggleTagFilter(tag.slug);
    tags.append(b);
  }
  if (!detailRow.tags.length) tags.append(" none ");
  const edit = document.createElement("button");
  edit.type = "button";
  edit.className = "text-button";
  edit.textContent = "Edit tags…";
  edit.onclick = () => openQuickTag(edit, [detailRow.record_sha256]);
  tags.append(edit);
  const notes = document.createElement("div");
  notes.className = "detail-notes";
  const nlabel = document.createElement("strong");
  nlabel.textContent = "Findings";
  notes.append(nlabel);
  for (const id of detailRow.annotations) {
    const note = reviews.annotations.find((n) => n.id === id);
    const b = document.createElement("button");
    b.type = "button";
    b.className = "text-button";
    b.textContent = `#${id} ${note ? noteTitle(note) : ""}`;
    b.onclick = () => showNotes([id]);
    notes.append(b);
  }
  if (!detailRow.annotations.length) notes.append(" none");
  const addNote = document.createElement("button");
  addNote.type = "button";
  addNote.className = "text-button";
  addNote.textContent = "Add to finding…";
  addNote.onclick = () => openNoteMenu(addNote, [detailRow.record_sha256]);
  notes.append(addNote);
  target.append(tags, notes);
  if ((detailRow.detections || []).length) {
    const det = document.createElement("div");
    det.className = "detail-tags";
    const dlabel = document.createElement("strong");
    dlabel.textContent = "Suzaku";
    det.append(dlabel);
    for (const d of detailRow.detections) {
      const b = document.createElement("button");
      b.type = "button";
      b.className = "full-tag";
      b.title = `${[...d.tactics, ...d.techniques].join(", ")}\nFilter to this rule`;
      b.append(levelBadge(d.level), d.title);
      b.onclick = () => toggleRuleFilter(d.rule_id);
      det.append(b);
    }
    target.append(det);
  }
}

async function detail(row) {
  try {
    const data = await request(`/api/events/${row.id}`);
    detailRow = row.record_sha256 ? row : null;
    $("detail-id").textContent =
      `${data.event_id} · ${row.time_local ? row.time_local + " " + meta.timezone : ""}`;
    eventCommandLinks(data.ssm_commands);
    // Format using token-aware whitespace only: do not parse/stringify numeric evidence in JavaScript.
    let indent = 0,
      quoted = false,
      escaped = false,
      output = "";
    for (const char of data.raw_json) {
      if (quoted) {
        output += char;
        if (escaped) escaped = false;
        else if (char === "\\") escaped = true;
        else if (char === '"') quoted = false;
      } else if (char === '"') {
        quoted = true;
        output += char;
      } else if (char === "{" || char === "[") {
        output += char + "\n" + "  ".repeat(++indent);
      } else if (char === "}" || char === "]") {
        output += "\n" + "  ".repeat(--indent) + char;
      } else if (char === ",") output += ",\n" + "  ".repeat(indent);
      else if (char === ":") output += ": ";
      else if (!/\s/.test(char)) output += char;
    }
    $("raw-event").textContent = output;
    $("record-hash").textContent =
      "Canonical record SHA-256: " + data.record_sha256;
    const rows = table.getRows();
    const index = rows.findIndex((r) => r.getData().id === row.id);
    $("detail-prev").hidden = $("detail-next").hidden = index < 0;
    $("detail-prev").disabled = index <= 0;
    $("detail-next").disabled = index < 0 || index >= rows.length - 1;
    document
      .querySelectorAll("#events .tabulator-row.inspected")
      .forEach((r) => r.classList.remove("inspected"));
    if (index >= 0) rows[index].getElement().classList.add("inspected");
    detailFindings();
    openDetail();
  } catch (e) {
    error(e.message);
  }
}

function step(delta) {
  if (!$("detail").open || !detailRow) return;
  const rows = table.getRows();
  const index = rows.findIndex((r) => r.getData().id === detailRow.id);
  const next = rows[index + delta];
  if (!next) return;
  table.scrollToRow(next, "nearest", false);
  detail(next.getData());
}

async function columnSummary(title, field, match) {
  if (!lastSelection) return;
  const requestId = ++summaryRequest;
  $("column-summary-title").textContent =
    `${title} · ${match ? "value prevalence" : "value frequency"}`;
  $("cell-summary-value").hidden = !match;
  $("cell-summary-value").textContent = match
    ? match.value === null
      ? "(missing)"
      : match.value === ""
        ? "(empty string)"
        : match.value
    : "";
  document.querySelector(".value-rankings").hidden = !!match;
  $("summary-note").textContent = match
    ? "Exact value match across the full applied time range, search and filters, not just this page. Missing and empty strings are distinct."
    : "Full applied time range and filters, not just this page. Ties use value order. Missing and empty values are included. Lists can overlap when fewer than 10 values exist. Use = / ≠ to add a filter.";
  $("column-summary-status").textContent = "Counting all matching events…";
  $("top-values").replaceChildren();
  $("bottom-values").replaceChildren();
  if (!$("column-summary").open) $("column-summary").showModal();
  const pivots = (value) => {
    const wrap = document.createElement("span");
    wrap.className = "pivots";
    for (const [label, op] of [
      ["=", "eq"],
      ["≠", "neq"],
    ]) {
      const b = document.createElement("button");
      b.type = "button";
      b.textContent = label;
      b.title = `Add filter: ${title} ${label} this value`;
      b.onclick = () => {
        $("column-summary").close();
        addFilter(
          field,
          value === null ? (op === "eq" ? "missing" : "not_missing") : op,
          value ?? "",
        );
      };
      wrap.append(b);
    }
    return wrap;
  };
  try {
    const data = await request("/api/column-values", {
      ...lastSelection,
      field,
      ...match,
    });
    if (requestId !== summaryRequest) return;
    if (match) {
      const percent = new Intl.NumberFormat("en-US", {
        style: "percent",
        maximumFractionDigits: 4,
      }).format(data.total ? data.events / data.total : 0);
      $("column-summary-status").replaceChildren(
        `${number(data.events)} of ${number(data.total)} matching events · ${percent} `,
        pivots(match.value),
      );
      return;
    }
    $("column-summary-status").textContent =
      `${number(data.total)} matching events · ${number(data.distinct_values)} distinct values`;
    for (const [id, rows] of [
      ["top-values", data.top],
      ["bottom-values", data.bottom],
    ]) {
      for (const row of rows) {
        const item = document.createElement("li");
        const value = document.createElement("span");
        value.textContent =
          row.value === null
            ? "(missing)"
            : row.value === ""
              ? "(empty string)"
              : row.value;
        const count = document.createElement("strong");
        count.textContent = number(row.events);
        count.setAttribute("aria-label", `${row.events} events`);
        item.append(value, count, pivots(row.value));
        $(id).append(item);
      }
      if (!rows.length) {
        const item = document.createElement("li");
        item.textContent = "No matching values";
        $(id).append(item);
      }
    }
  } catch (e) {
    if (requestId === summaryRequest)
      $("column-summary-status").textContent = e.message;
  }
}

// ---- Charts -----------------------------------------------------------------------------------
function svgBuilder(width, height) {
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("viewBox", `0 0 ${width} ${height}`);
  svg.setAttribute("preserveAspectRatio", "none");
  const element = (tag, attrs, text) => {
    const el = document.createElementNS(svg.namespaceURI, tag);
    for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, v);
    if (text !== undefined) el.textContent = text;
    svg.append(el);
    return el;
  };
  return [svg, element];
}

function timeline() {
  if (!meta || !$("timeline").clientWidth) return;
  const max = Math.max(...meta.histogram.map((r) => r.total)),
    width = $("timeline").clientWidth,
    gap = width / meta.histogram.length;
  const [svg, element] = svgBuilder(width, 46);
  meta.histogram.forEach((r, i) => {
    const ms = r.start_ms,
      height = (r.total / max) * 32;
    const bar = element("rect", {
      x: i * gap + 1,
      y: 34 - height,
      width: Math.max(1, gap - 2),
      height,
      class: "bar",
      "data-ms": ms,
      "data-end-ms": r.end_ms,
      tabindex: 0,
      role: "button",
      "aria-label": `${r.day}: ${r.total} events; select this day`,
    });
    const title = document.createElementNS(svg.namespaceURI, "title");
    title.textContent = `${r.day}: ${number(r.total)} events; ${r.ssm} SSM commands/sessions`;
    bar.append(title);
    const choose = () => range(ms, r.end_ms);
    bar.addEventListener("click", choose);
    bar.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        choose();
      }
    });
    if (r.ssm)
      element("rect", {
        x: i * gap + 1,
        y: 34 - Math.max(2, (r.ssm / max) * 32),
        width: Math.max(1, gap - 2),
        height: Math.max(2, (r.ssm / max) * 32),
        fill: "#b84441",
        "pointer-events": "none",
      });
    if (
      i === 0 ||
      i === meta.histogram.length - 1 ||
      (i % Math.max(7, Math.ceil((meta.histogram.length * 85) / width)) === 0 &&
        i * gap < width - 90)
    )
      element(
        "text",
        {
          x: i * gap + 1,
          y: 45,
          "text-anchor": i === meta.histogram.length - 1 ? "end" : "start",
        },
        r.day.slice(5),
      );
  });
  $("timeline").replaceChildren(svg);
}

const compact = (n) =>
  new Intl.NumberFormat("en-US", {
    notation: "compact",
    maximumFractionDigits: 1,
  }).format(n);

function frequency(data, context) {
  $("frequency").replaceChildren();
  if (data.error) {
    $("frequency-summary").textContent = data.error;
    $("histogram-sql").textContent = data.error;
    return;
  }
  const ctx =
    context && !context.error
      ? new Map(context.data.map((r) => [r.start_ms, r.events]))
      : null;
  const filteredPeak = Math.max(0, ...data.data.map((r) => r.events));
  const peak = Math.max(filteredPeak, ...(ctx ? ctx.values() : []));
  $("frequency-summary").textContent =
    `${number(data.total)} selected events · ${number(data.data.length)} buckets of ${number(data.bucket_minutes)} min · peak ${number(filteredPeak)}` +
    " · amber marks below baseline = zero; positive bars ≥ 1px" +
    (ctx ? ` · context ${number(context.total)} events` : "") +
    (context?.error ? ` · context unavailable: ${context.error}` : "");
  $("histogram-sql").textContent =
    data.sql +
    "\n\n-- Bound parameters\n" +
    JSON.stringify(data.params, null, 2);
  const width = $("frequency").clientWidth,
    left = 44,
    top = 8,
    base = 92,
    plot = width - left - 8,
    stepWidth = plot / data.data.length;
  if (!width) return;
  const [svg, element] = svgBuilder(width, 110);
  for (const fraction of [0, 0.5, 1]) {
    const y = base - fraction * (base - top);
    element("line", {
      x1: left,
      x2: width - 8,
      y1: y,
      y2: y,
      stroke: fraction ? "#e3ecf2" : "#c9d9e4",
    });
    element(
      "text",
      { x: left - 5, y: y + 3, "text-anchor": "end" },
      fraction
        ? peak * fraction < 10000
          ? number(Math.round(peak * fraction))
          : compact(peak * fraction)
        : "0",
    );
  }
  const ticks = Math.max(1, Math.ceil((data.data.length * 110) / plot));
  const scale = (n) => (peak ? (n / peak) * (base - top) : 0);
  data.data.forEach((row, i) => {
    const x = left + i * stepWidth,
      w = Math.max(0.6, stepWidth - (stepWidth > 4 ? 1 : 0));
    if (ctx) {
      const c = ctx.get(row.start_ms) || 0;
      element("rect", {
        x,
        y: base - (c ? Math.max(1, scale(c)) : 0),
        width: w,
        height: c ? Math.max(1, scale(c)) : 0,
        class: "context-bar",
        "pointer-events": "none",
      });
    }
    const height = row.events ? Math.max(1, scale(row.events)) : 2;
    const bar = element("rect", {
      x,
      y: row.events ? base - height : base + 2,
      width: w,
      height,
      class: row.events ? "frequency-bar" : "frequency-bar zero-bucket",
      tabindex: 0,
      role: "button",
      "data-index": i,
      "aria-label": `${row.bucket_start_local} ${meta.timezone}: ${row.events} events; narrow to this bucket`,
    });
    const title = document.createElementNS(svg.namespaceURI, "title");
    title.textContent =
      `${row.bucket_start_local} ${meta.timezone}: ${number(row.events)} selected events` +
      (ctx ? ` of ${number(ctx.get(row.start_ms) || 0)} in context` : "") +
      ` (${data.bucket_minutes} minute bucket; boundary buckets may be partial)`;
    bar.append(title);
    bar.addEventListener("keydown", (event) => {
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        pickBuckets(data, i, i);
      }
    });
    if (i === 0 || (i % ticks === 0 && i * stepWidth < plot - 105))
      element(
        "text",
        { x, y: 106 },
        data.bucket_minutes >= 1440
          ? row.bucket_start_local.slice(5, 10)
          : row.bucket_start_local.slice(5, 16),
      );
  });
  // Brush: drag to select contiguous buckets; a click without dragging narrows to one bucket.
  const brush = element("rect", {
    x: 0,
    y: top,
    width: 0,
    height: base - top,
    class: "brush",
    "pointer-events": "none",
  });
  const index = (clientX) =>
    Math.min(
      data.data.length - 1,
      Math.max(
        0,
        Math.floor(
          (clientX - svg.getBoundingClientRect().left - left) / stepWidth,
        ),
      ),
    );
  let from = null,
    startX = 0;
  svg.addEventListener("pointerdown", (e) => {
    if (e.button !== 0) return;
    from = index(e.clientX);
    startX = e.clientX;
    svg.setPointerCapture(e.pointerId);
  });
  svg.addEventListener("pointermove", (e) => {
    if (from === null) return;
    const to = index(e.clientX),
      a = Math.min(from, to),
      b = Math.max(from, to);
    brush.setAttribute("x", left + a * stepWidth);
    brush.setAttribute("width", (b - a + 1) * stepWidth);
  });
  svg.addEventListener("pointerup", (e) => {
    if (from === null) return;
    const to = Math.abs(e.clientX - startX) < 4 ? from : index(e.clientX);
    const a = Math.min(from, to),
      b = Math.max(from, to);
    from = null;
    pickBuckets(data, a, b);
  });
  $("frequency").append(svg);
}

function pickBuckets(data, a, b) {
  const start = data.data[a].start_ms;
  const end = data.data[b].end_ms;
  range(Math.max(start, applied.start), Math.min(end, applied.end));
}

// ---- Event grid ------------------------------------------------------------------------------
let tableReady = false;
function fitGrid() {
  if (!tableReady || commandsActive) return;
  const h = innerHeight - $("query-bar").offsetHeight - 6;
  table.setHeight(Math.max(260, h));
}

function eventReviewAdd(row, kind) {
  const b = document.createElement("button");
  b.type = "button";
  b.className = "review-add";
  b.textContent = "+";
  b.title = kind === "tags" ? "Tag this event" : "Add this event to a finding";
  b.setAttribute("aria-label", b.title);
  b.onclick = (e) => {
    e.stopPropagation();
    if (kind === "tags") openQuickTag(b, [row.record_sha256]);
    else openNoteMenu(b, [row.record_sha256]);
  };
  return b;
}

function tagCell(cell) {
  const d = cell.getRow().getData();
  const wrap = document.createElement("span");
  wrap.className = "tag-markers review-cell";
  const visible = d.tags.length > 3 ? d.tags.slice(0, 2) : d.tags;
  for (const tag of visible) {
    const s = swatch(tag, (e) => {
      e.stopPropagation();
      tagPopover(e.currentTarget, d);
    });
    s.setAttribute(
      "aria-label",
      `Tag ${tag.slug}; show all tags on this event`,
    );
    wrap.append(s);
  }
  if (d.tags.length > visible.length) {
    const more = document.createElement("button");
    more.type = "button";
    more.className = "tag-more";
    more.textContent = `+${d.tags.length - visible.length}`;
    more.title = d.tags.map((t) => t.slug).join(", ");
    more.setAttribute("aria-label", `${d.tags.length} tags; show all`);
    more.onclick = (e) => {
      e.stopPropagation();
      tagPopover(more, d);
    };
    wrap.append(more);
  }
  wrap.append(eventReviewAdd(d, "tags"));
  return wrap;
}

function tagPopover(anchor, row) {
  const menu = $("tag-popover");
  const title = document.createElement("p");
  title.className = "menu-title";
  title.textContent = `Tags on this event (${row.tags.length})`;
  const list = document.createElement("ul");
  for (const tag of row.tags) {
    const li = document.createElement("li");
    const b = document.createElement("button");
    b.type = "button";
    b.className = "full-tag";
    b.title = "Filter to this tag";
    b.append(swatch(tag), tag.slug);
    b.onclick = () => {
      menu.hidePopover();
      toggleTagFilter(tag.slug);
    };
    li.append(b);
    list.append(li);
  }
  const edit = document.createElement("button");
  edit.type = "button";
  edit.className = "text-button";
  edit.textContent = "Edit tags on this event…";
  edit.onclick = () => {
    menu.hidePopover();
    openQuickTag(anchor, [row.record_sha256]);
  };
  menu.replaceChildren(title, list, edit);
  placeMenu(menu, anchor);
}

function noteCell(cell) {
  const d = cell.getRow().getData();
  const wrap = document.createElement("span");
  wrap.className = "review-cell";
  wrap.append(eventReviewAdd(d, "notes"));
  if (!d.annotations.length) return wrap;
  const b = document.createElement("button");
  b.type = "button";
  b.className = "note-marker";
  b.innerHTML =
    '<svg viewBox="0 0 16 16" aria-hidden="true"><path d="M3 1.5h7l3 3v10H3z M10 1.5v3h3 M5 8h6 M5 11h6"/></svg>';
  b.append(d.annotations.length > 1 ? String(d.annotations.length) : "");
  b.title = d.annotations
    .map(
      (id) =>
        `#${id} ${noteTitle(reviews.annotations.find((n) => n.id === id))}`,
    )
    .join("\n");
  b.setAttribute(
    "aria-label",
    `${d.annotations.length} findings; show them in the sidebar`,
  );
  b.onclick = (e) => {
    e.stopPropagation();
    showNotes(d.annotations);
  };
  wrap.prepend(b);
  return wrap;
}

async function init() {
  meta = await request("/api/meta");
  const preferred = localStorage.getItem("timezone");
  if (meta.timezones.includes(preferred))
    meta = await request("/api/meta", { timezone: preferred });
  for (const zone of meta.timezones)
    $("timezone").append(new Option(zone, zone));
  $("timezone").value = meta.timezone;
  $("start").setAttribute("aria-label", `From (inclusive), ${meta.timezone}`);
  $("end").setAttribute("aria-label", `Until (exclusive), ${meta.timezone}`);
  $("timezone").onchange = () =>
    apply({ ...applied, timezone: $("timezone").value });
  applied = normalize({});
  queryHistory.push(applied);
  historyPos = 0;
  setSidebar(localStorage.getItem("sidebar-expanded") === "1");
  $("expand-sidebar").onclick = () => {
    setSidebar(true);
    $("collapse-sidebar").focus();
  };
  $("collapse-sidebar").onclick = () => {
    setSidebar(false);
    $("expand-sidebar").focus();
  };
  $("rail-all-tags").onclick = () => {
    setSidebar(true);
    sidebarTab("tags");
    $("tag-search").focus();
  };
  $("rail-tags").onscroll = () => ($("rail-tip").hidden = true);
  $("tags-tab").onclick = () => sidebarTab("tags");
  $("notes-tab").onclick = () => sidebarTab("notes");
  $("detections-tab").onclick = () => sidebarTab("detections");
  $("rule-search").oninput = renderDetections;
  $("tag-search").oninput = renderTags;
  $("note-search").oninput = renderNotes;
  $("recolor").onchange = () =>
    writeReview({
      action: "color",
      slug: $("recolor").dataset.slug,
      color: $("recolor").value,
    });
  $("events-tab").onclick = () => switchView(false);
  $("commands-tab").onclick = () => switchView(true);
  $("show-sql").onclick = () => {
    if (commandsActive) switchView(false);
    $("sql-panel").open = true;
    $("sql-panel").scrollIntoView();
  };
  $("command-search-form").onsubmit = (e) => {
    e.preventDefault();
    if (commandLog) loadLog({ fresh: true });
    else loadCommands();
  };
  $("more-commands").onclick = () => loadCommands(true);
  $("command-detail-layout").onclick = () => commandLayout(false);
  $("command-sheet-layout").onclick = () => commandLayout(true);
  $("command-log-layout").onclick = () => commandLayout(false, true);
  logObserver = new IntersectionObserver(
    (entries) => {
      if (entries.some((entry) => entry.isIntersecting))
        loadLog({ more: true });
    },
    { rootMargin: "1200px 0px" },
  );
  $("more-log").onclick = () => loadLog({ retry: logFailure });
  $("refresh-log").onclick = () =>
    loadLog({
      retry: { selection: logSelection, page: 1, restore: logAnchor() },
    });
  $("log-search-scope").onchange = () => loadLog({ fresh: true });
  $("log-editor-form").onsubmit = (e) => {
    e.preventDefault();
    saveLogEntry();
  };
  for (const id of ["log-edit-text", "log-edit-tags", "log-edit-finding"])
    $(id).oninput = editLogDraft;
  $("log-editor-close").onclick = closeLogEditor;
  $("log-editor").onkeydown = (e) => {
    if (e.key === "Escape") {
      e.preventDefault();
      closeLogEditor();
    }
  };
  $("log-latest").onclick = readLatestLog;
  $("log-discard").onclick = discardLogDraft;
  $("log-copy-raw").onclick = copyRawToLog;
  for (const button of document.querySelectorAll(".log-decode"))
    button.onclick = () => decodeLog(button.dataset.encoding);
  $("log-use-latest").onclick = () => adoptLatestLog(false);
  $("log-replace-latest").onclick = () => adoptLatestLog(true);
  // Drafts are deliberately not stored in localStorage; warn before losing them instead.
  addEventListener("beforeunload", (e) => {
    if ([...logDrafts.values()].some((d) => d.dirty)) {
      e.preventDefault();
      e.returnValue = "";
    }
  });
  $("more-sheet").onclick = loadMoreSheet;
  $("close-sheet-cell").onclick = () => $("sheet-cell-dialog").close();
  $("sheet-density").onchange = () => {
    $("command-sheet").classList.toggle(
      "expanded",
      $("sheet-density").value === "expanded",
    );
    sheetTable.redraw(true);
    sheetTable.getRows().forEach((row) => row.normalizeHeight());
  };
  for (const [key, [label]] of Object.entries(OPS))
    $("filter-op").add(new Option(label, key));
  for (const [key, label] of Object.entries(meta.fields))
    $("filter-field").add(new Option(label, key));
  $("filter-field").onchange = filterChoices;
  $("filter-op").onchange = () => {
    filterChoices();
    draftState();
  };
  $("filter-value").oninput = draftState;
  $("filter-value").onkeydown = (e) => {
    if (e.key === "Enter") {
      e.preventDefault();
      $("filter-save").click();
    } else if (e.key === "Escape") {
      closeFilterEditor();
      draftState();
    }
  };
  $("add-filter").onclick = () => openFilterEditor();
  $("filter-cancel").onclick = () => {
    closeFilterEditor();
    draftState();
  };
  $("filter-save").onclick = () => {
    const value = filterEditorValue();
    if (!value) return $("filter-value").focus();
    const filters = [...applied.filters];
    if (editingFilter === null) filters.push(value);
    else filters[editingFilter] = value;
    apply({ ...applied, filters });
  };
  $("search").oninput = draftState;
  $("start").oninput = $("end").oninput = () => {
    paintSelection();
    draftState();
  };
  for (const id of ["start", "end"])
    $(id).onkeydown = (e) => {
      if (e.key === "Enter") runDraft();
    };
  $("revert").onclick = () => {
    closeFilterEditor();
    syncInputs();
  };
  $("back").onclick = () => go(-1);
  $("forward").onclick = () => go(1);
  await Promise.all([refreshReviews(), loadDetections()]);
  $("quick-tag").onclick = () =>
    openQuickTag($("quick-tag"), [...selectedEvents]);
  $("add-to-note").onclick = () => openNoteMenu($("add-to-note"));
  $("note-menu-search").oninput = renderNoteMenu;
  $("new-note").onclick = () => {
    $("note-menu").hidePopover();
    noteDialog(null, noteMenuHashes);
  };
  $("tag-slug").oninput = renderQuickTag;
  $("tag-slug").onkeydown = (e) => {
    if (e.key === "Enter") {
      e.preventDefault();
      createTag().catch(() => {});
    }
  };
  $("create-tag").onclick = () => createTag().catch(() => {});
  $("refresh-stale").onclick = reload;
  $("close-review").onclick = () => $("review-dialog").close();
  $("clear-selection").onclick = () => {
    selectedEvents.clear();
    table.redraw(true);
    selectionStatus();
  };
  $("note-body").oninput = () =>
    markdown($("note-preview"), $("note-body").value);
  $("save-note").onclick = async () => {
    try {
      const result = await request(
        "/api/reviews",
        editingNote === null
          ? {
              action: "annotate",
              hashes: reviewHashes,
              body: $("note-body").value,
              context: applied,
            }
          : {
              action: "edit",
              id: editingNote.id,
              updated: editingNote.updated,
              body: $("note-body").value,
            },
      );
      $("review-dialog").close();
      if (editingNote === null) {
        // Already saved; patch rows and counts without re-sending the note.
        await refreshReviews();
        for (const row of table.getRows()) {
          const d = row.getData();
          if (
            reviewHashes.includes(d.record_sha256) &&
            !d.annotations.includes(result.id)
          )
            row.update({ annotations: [...d.annotations, result.id] });
        }
        if (detailRow && reviewHashes.includes(detailRow.record_sha256)) {
          if (!detailRow.annotations.includes(result.id))
            detailRow.annotations = [...detailRow.annotations, result.id];
          detailFindings();
        }
        showNotes([result.id]);
        noteScope = null;
        renderNotes();
      } else {
        await refreshReviews();
      }
    } catch (e) {
      $("review-error").textContent = e.message;
      $("review-error").hidden = false;
    }
  };
  $("coverage").textContent =
    `${number(meta.total)} events · ${local(meta.start_ms).slice(0, 10)} to ${local(meta.end_ms).slice(0, 10)} ${meta.timezone}`;
  timeline();
  noUiSlider.create($("time-slider"), {
    start: [meta.start_ms, meta.end_ms],
    range: { min: meta.start_ms, max: meta.end_ms },
    connect: true,
    behaviour: "drag-tap",
    step: 1000,
    margin: 1000,
    animate: false,
    keyboardMultiplier: 3600,
    handleAttributes: [
      { "aria-label": "Range start" },
      { "aria-label": "Range end" },
    ],
  });
  $("time-slider").noUiSlider.on("slide", (values) => {
    $("start").value = inputTime(Number(values[0]));
    $("end").value = inputTime(Number(values[1]));
    paintSelection();
  });
  $("time-slider").noUiSlider.on("change", (values) => {
    if (!updating) range(Number(values[0]), Number(values[1]));
  });
  const textColumn = (title, field, width, extra = {}) => ({
    title,
    field,
    width,
    titleFormatter: () => {
      const heading = document.createElement("span");
      heading.className = "column-heading";
      const label = document.createElement("span");
      label.textContent = title;
      const button = document.createElement("button");
      button.type = "button";
      button.className = "column-summary-button";
      button.textContent = "≡";
      button.title = `Top / bottom 5 values: ${title}`;
      button.setAttribute("aria-label", `Summarize ${title}`);
      button.addEventListener("click", (event) => {
        event.stopPropagation();
        columnSummary(title, field);
      });
      button.addEventListener("keydown", (event) => event.stopPropagation());
      heading.append(label, button);
      return heading;
    },
    formatter: (cell) => {
      const wrapper = document.createElement("span");
      wrapper.className = "cell-content";
      const value = cell.getValue() ?? null;
      const text = document.createElement("span");
      text.className = "cell-text";
      text.textContent = value ?? "";
      const actions = document.createElement("span");
      actions.className = "cell-actions";
      for (const action of ["copy", "prevalence", "filter"]) {
        const button = document.createElement("button");
        button.type = "button";
        button.className = `cell-${action}`;
        button.setAttribute(
          "aria-label",
          `${action === "copy" ? "Copy" : action === "filter" ? "Filter by" : "Prevalence of"} ${title} value`,
        );
        button.title =
          action === "copy"
            ? "Copy full value"
            : action === "filter"
              ? "Add is / is not filter"
              : "Prevalence in filtered selection";
        button.innerHTML =
          action === "copy"
            ? '<svg viewBox="0 0 16 16" aria-hidden="true"><rect x="5" y="5" width="8" height="8" rx="1"/><path d="M3 10H2V2h8v1"/></svg>'
            : action === "filter"
              ? '<svg viewBox="0 0 16 16" aria-hidden="true"><path d="M2 3h12l-5 5v5l-2-1V8Z"/></svg>'
              : "%";
        const icon = button.innerHTML;
        button.addEventListener("keydown", (event) => event.stopPropagation());
        button.addEventListener("click", async (event) => {
          event.stopPropagation();
          if (action === "filter") {
            cellFilter = { field, value };
            $("filter-cell-value").textContent =
              `${title}: ${value === null ? "(missing)" : value === "" ? "(empty string)" : value}`;
            placeMenu($("cell-filter-menu"), button);
            $("cell-filter-is").focus();
            return;
          }
          if (action === "prevalence") {
            columnSummary(title, field, { value });
            return;
          }
          try {
            await navigator.clipboard.writeText(value ?? "");
            button.textContent = "✓";
            $("cell-feedback").textContent = `${title} value copied`;
            setTimeout(() => {
              button.innerHTML = icon;
            }, 1400);
          } catch {
            error(
              "Clipboard unavailable. Select the cell text and copy it manually.",
            );
          }
        });
        actions.append(button);
      }
      wrapper.append(text, actions);
      return wrapper;
    },
    tooltip: (_event, cell) => {
      const tip = document.createElement("span");
      tip.textContent = cell.getValue() ?? "";
      return tip;
    },
    ...extra,
  });
  table = new Tabulator("#events", {
    height: "500px",
    layout: "fitDataStretch",
    placeholder: "No matching events. Widen the time range or remove a scope.",
    sortMode: "remote",
    initialSort: [{ column: "time_local", dir: "desc" }],
    ajaxURL: "/api/events",
    ajaxRequestFunc: async (_url, _config, params) => {
      const requestId = ++latestQuery;
      loadingFirst = true;
      loadingMore = false;
      nextPage = 2;
      selectedEvents.clear();
      selectionStatus();
      $("column-summary").close();
      $("cell-filter-menu").hidePopover();
      try {
        $("query-time").textContent = "Running…";
        $("load-status").textContent = "Loading…";
        $("frequency-summary").textContent =
          "Updating selected event frequency…";
        const selection = query();
        const bucket_minutes =
          $("bucket").value === "custom"
            ? $("custom-bucket").value
            : $("bucket").value;
        const [result, histogram, context] = await Promise.all([
          request("/api/events", {
            ...selection,
            page: 1,
            size: 100,
            sorters: params.sort,
          }),
          request("/api/histogram", { ...selection, bucket_minutes }).catch(
            (e) => ({ error: e.message }),
          ),
          $("show-context").checked
            ? request("/api/histogram", {
                timezone: selection.timezone,
                start: selection.start,
                end: selection.end,
                bucket_minutes,
              }).catch((e) => ({ error: e.message }))
            : null,
        ]);
        // Tabulator ignores stale row loads; keep the count and SQL in sync with it.
        if (requestId !== latestQuery) return [];
        // Agents (MCP) write the same sidecar: every run also refreshes tag/note lists.
        refreshReviews().catch((e) => error(e.message));
        lastResult = result;
        lastSelection = selection;
        lastHistogram = histogram;
        lastContext = context;
        frequency(histogram, context);
        $("result-count").textContent = `${number(result.last_row)} matching`;
        $("query-time").textContent = `${number(result.elapsed_ms)} ms`;
        $("sql").textContent =
          result.sql +
          "\n\n-- Bound parameters\n" +
          JSON.stringify(result.params, null, 2);
        error("");
        return result.data;
      } catch (e) {
        if (requestId === latestQuery) {
          $("query-time").textContent = "Query failed";
          error(e.message);
        }
        throw e;
      }
    },
    rowFormatter: (row) => {
      const d = row.getData();
      row
        .getElement()
        .classList.toggle(
          "ssm-row",
          d.event_source === "ssm.amazonaws.com" &&
            ["SendCommand", "StartSession", "CancelCommand"].includes(
              d.event_name,
            ),
        );
    },
    columns: [
      {
        title: "",
        field: "review",
        width: 34,
        frozen: true,
        headerSort: false,
        titleFormatter: () => {
          const input = document.createElement("input");
          input.type = "checkbox";
          input.setAttribute("aria-label", "Select all loaded events");
          input.title = "Select all loaded rows (not unloaded matches)";
          input.onchange = () => {
            for (const row of table.getData()) {
              if (input.checked) selectedEvents.add(row.record_sha256);
              else selectedEvents.delete(row.record_sha256);
            }
            table.redraw(true);
            selectionStatus();
          };
          return input;
        },
        formatter: (cell) => {
          const d = cell.getRow().getData();
          const check = document.createElement("input");
          check.type = "checkbox";
          check.checked = selectedEvents.has(d.record_sha256);
          check.setAttribute(
            "aria-label",
            `Select event ${d.event_id || d.id}`,
          );
          check.onclick = (e) => e.stopPropagation();
          check.onchange = () => {
            if (check.checked) selectedEvents.add(d.record_sha256);
            else selectedEvents.delete(d.record_sha256);
            selectionStatus();
          };
          return check;
        },
        cellClick: (e) => e.stopPropagation(),
      },
      {
        title: "Tags",
        field: "tags",
        width: 78,
        frozen: true,
        headerSort: false,
        formatter: tagCell,
      },
      {
        title: "Findings",
        field: "annotations",
        width: 74,
        frozen: true,
        headerSort: false,
        formatter: noteCell,
      },
      {
        title: "Sigma",
        field: "detections",
        width: 58,
        frozen: true,
        headerSort: false,
        visible: meta.detections_loaded,
        headerTooltip: "Suzaku detections: most severe level and match count",
        formatter: detectionCell,
      },
      textColumn("Local time", "time_local", 150, { cssClass: "tabular-cell" }),
      textColumn("Operation", "event_name", 180),
      textColumn("AWS service", "event_source", 170),
      textColumn("Identity", "identity", 330),
      textColumn("Source IP", "source_ip", 130, { cssClass: "mono-cell" }),
      textColumn("Country", "country", 120),
      textColumn("City", "city", 120, { visible: !!meta.enrichment }),
      textColumn("ASN", "asn", 90, { visible: !!meta.enrichment }),
      textColumn("Target", "target", 220),
      textColumn("Error", "error_code", 150),
      textColumn("Access key ID", "key_id", 190, {
        visible: false,
        cssClass: "mono-cell",
      }),
      textColumn("Identity type", "identity_type", 120),
      textColumn("SSM document", "document_name", 210),
      textColumn("Network / ISP", "isp", 160),
      textColumn("IP attributes", "ip_info", 320, {
        // Provider-specific values (e.g. a proxy score) only exist when a JSONL source supplied them.
        visible: !!meta.enrichment?.sources.some(
          (s) => s.attribute_keys.length,
        ),
      }),
      textColumn("Region", "region", 125),
      textColumn("Event ID", "event_id", 290, { cssClass: "mono-cell" }),
    ],
  });
  table.on("tableBuilt", () => {
    tableReady = true;
    fitGrid();
  });
  table.on("dataProcessed", () => {
    loadingFirst = false;
    selectionStatus();
    loadStatus();
  });
  table.on("scrollVertical", (top) => {
    const holder = document.querySelector("#events .tabulator-tableholder");
    if (holder.scrollHeight - holder.clientHeight - top < 150) loadMore();
  });
  table.on("rowClick", (_event, row) => detail(row.getData()));
  for (const [id, op] of [
    ["cell-filter-is", "eq"],
    ["cell-filter-is-not", "neq"],
  ]) {
    $(id).addEventListener("click", () => {
      const { field, value } = cellFilter;
      $("cell-filter-menu").hidePopover();
      addFilter(
        field,
        value === null ? (op === "eq" ? "missing" : "not_missing") : op,
        value ?? "",
      );
    });
  }
  $("query-form").addEventListener("submit", (e) => {
    e.preventDefault();
    runDraft();
  });
  $("apply-time").addEventListener("click", runDraft);
  $("all-time").addEventListener("click", () =>
    range(meta.start_ms, meta.end_ms),
  );
  $("last-week").addEventListener("click", () =>
    range(Math.max(meta.start_ms, meta.end_ms - 7 * 86400000), meta.end_ms),
  );
  $("last-three-days").addEventListener("click", () =>
    range(Math.max(meta.start_ms, meta.end_ms - 3 * 86400000), meta.end_ms),
  );
  $("bucket").addEventListener("change", () => {
    $("custom-bucket").hidden = $("bucket").value !== "custom";
    reload();
  });
  $("custom-bucket").addEventListener("change", reload);
  $("show-context").addEventListener("change", reload);
  $("toggle-charts").addEventListener("click", () => {
    const open = $("charts").hidden;
    $("charts").hidden = !open;
    $("toggle-charts").setAttribute("aria-expanded", String(open));
    $("toggle-charts").textContent = open ? "Hide histogram" : "Show histogram";
    if (open) {
      timeline();
      paintSelection();
      if (lastHistogram) frequency(lastHistogram, lastContext);
    }
  });
  window.addEventListener("resize", () => {
    timeline();
    paintSelection();
    if (lastHistogram) frequency(lastHistogram, lastContext);
    fitGrid();
  });
  new ResizeObserver(fitGrid).observe($("query-bar"));
  $("ssm-only").addEventListener("click", () =>
    apply({
      ...applied,
      filters: [
        ...applied.filters.filter(
          (f) => !["event_source", "event_name"].includes(f.field),
        ),
        { field: "event_source", op: "eq", value: "ssm.amazonaws.com" },
        {
          field: "event_name",
          op: "in",
          value: "SendCommand, StartSession, CancelCommand",
        },
      ],
    }),
  );
  $("clear").addEventListener("click", () =>
    apply({ start: applied.start, end: applied.end }),
  );
  $("show-keys").addEventListener("change", (e) =>
    table[e.target.checked ? "showColumn" : "hideColumn"]("key_id"),
  );
  $("close-detail").addEventListener("click", () => $("detail").close());
  $("detail").addEventListener("close", () =>
    document
      .querySelectorAll("#events .tabulator-row.inspected")
      .forEach((r) => r.classList.remove("inspected")),
  );
  $("detail-prev").onclick = () => step(-1);
  $("detail-next").onclick = () => step(1);
  $("close-summary").addEventListener("click", () =>
    $("column-summary").close(),
  );
  $("column-summary").addEventListener("close", () => ++summaryRequest);
  document.addEventListener("keydown", (e) => {
    const typing = /^(INPUT|TEXTAREA|SELECT)$/.test(e.target.tagName);
    if (e.altKey && (e.key === "ArrowLeft" || e.key === "ArrowRight")) {
      e.preventDefault();
      go(e.key === "ArrowLeft" ? -1 : 1);
    } else if (e.key === "Escape" && $("detail").open && !typing) {
      $("detail").close();
    } else if (typing || e.ctrlKey || e.metaKey || e.altKey || commandsActive) {
      return;
    } else if (e.key === "/") {
      e.preventDefault();
      $("search").focus();
    } else if (e.key === "t" && selectedEvents.size) {
      e.preventDefault();
      $("quick-tag").click();
    } else if (e.key === "j" || e.key === "k") {
      step(e.key === "j" ? 1 : -1);
    }
  });
  $("copy-sql").addEventListener("click", async () => {
    if (!lastResult) return;
    let index = 0;
    const sql = lastResult.sql.replace(/\?/g, () => {
      const value = lastResult.params[index++];
      return typeof value === "number"
        ? String(value)
        : "'" + value.replaceAll("'", "''") + "'";
    });
    try {
      await navigator.clipboard.writeText(sql + ";");
      $("copy-sql").textContent = "Copied";
      setTimeout(() => ($("copy-sql").textContent = "Copy SQL"), 1800);
    } catch {
      error(
        "Clipboard unavailable. Select and copy the SQL and parameters below.",
      );
    }
  });
  syncInputs();
  renderScopes();
}

// A little visitor from the hero artwork: ↑ ↑ ↓ ↓ ← → ← → B A.
(() => {
  const code = [
    "arrowup",
    "arrowup",
    "arrowdown",
    "arrowdown",
    "arrowleft",
    "arrowright",
    "arrowleft",
    "arrowright",
    "b",
    "a",
  ];
  let keys = [],
    visiting = false;
  const duck = new Image();
  duck.src = "/konami-duck.png";
  duck.alt = "";
  duck.className = "konami-duck";
  duck.setAttribute("aria-hidden", "true");

  async function quack() {
    // A short, nasal falling squawk, generated locally without an audio download.
    let audio;
    try {
      audio = new AudioContext();
      await audio.resume();
      const voice = audio.createOscillator();
      const filter = audio.createBiquadFilter();
      const volume = audio.createGain();
      const now = audio.currentTime;
      voice.type = "sawtooth";
      voice.frequency.setValueAtTime(320, now);
      voice.frequency.exponentialRampToValueAtTime(110, now + 0.32);
      filter.type = "bandpass";
      filter.frequency.setValueAtTime(1400, now);
      filter.frequency.exponentialRampToValueAtTime(650, now + 0.32);
      filter.Q.value = 2.5;
      volume.gain.setValueAtTime(0, now);
      volume.gain.linearRampToValueAtTime(0.35, now + 0.025);
      volume.gain.exponentialRampToValueAtTime(0.001, now + 0.36);
      voice.connect(filter).connect(volume).connect(audio.destination);
      voice.onended = () => audio.close().catch(() => {});
      voice.start(now);
      voice.stop(now + 0.38);
    } catch {
      // A browser without audio support should still get the duck.
      if (audio) audio.close().catch(() => {});
    }
  }

  document.addEventListener("keydown", (event) => {
    if (
      event.ctrlKey ||
      event.metaKey ||
      event.altKey ||
      event.isComposing ||
      event.target.isContentEditable ||
      event.target.closest("input, textarea, select")
    ) {
      keys = [];
      return;
    }
    if (event.repeat) return;
    keys = [...keys, event.key.toLowerCase()].slice(-code.length);
    if (!code.every((key, index) => keys[index] === key)) return;
    keys = [];
    if (visiting) return;
    visiting = true;
    document.body.append(duck);
    quack();
    setTimeout(() => {
      duck.remove();
      visiting = false;
    }, 4200);
  });
})();

init().catch((e) => error(e.message));
