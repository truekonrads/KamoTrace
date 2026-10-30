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
  latestQuery = 0;
const number = (n) => new Intl.NumberFormat("en-US").format(n);
const local = (ms) => new Date(ms + 7 * 3600000).toISOString().slice(0, 19);
const shown = (ms) => local(ms).replace("T", " ");
const epoch = (value) => Date.parse(value + "+07:00");
const wibTime = (value) =>
  Number.isFinite(Date.parse(value))
    ? shown(Date.parse(value)) + " WIB"
    : "Unknown time";
// 24-hour Jakarta text input: "YYYY-MM-DD HH:MM[:SS]" (a "T" separator is also accepted).
const parseInput = (value) => {
  const m = /^\s*(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2})(:\d{2})?\s*$/.exec(value);
  return m ? epoch(`${m[1]}T${m[2]}${m[3] || ":00"}`) : NaN;
};
let reviews = { annotations: [], tags: [] },
  editingNote = null;
const selectedEvents = new Set();
let reviewHashes = [],
  quickTagHashes = [];
let commandKey = null,
  commandsActive = false,
  commandPage = 1,
  commandRequest = 0,
  commandDetailRequest = 0;
let commandSheet = false,
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
    command_key: typeof s.command_key === "string" ? s.command_key : null,
    command_label: typeof s.command_label === "string" ? s.command_label : null,
  };
}

function apply(state, push = true) {
  const next = normalize(state);
  if (!(next.start < next.end)) {
    error("Choose a valid time range: start must be before the exclusive end.");
    return;
  }
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
    start: local(applied.start) + "+07:00",
    end: local(applied.end) + "+07:00",
    search: applied.search,
    tags: applied.tags,
    annotation_id: applied.annotation_id,
    rules: applied.rules,
    command_key: applied.command_key,
    filters: applied.filters,
  };
}

function syncInputs() {
  $("search").value = applied.search;
  $("start").value = shown(applied.start);
  $("end").value = shown(applied.end);
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
    error("Times must use YYYY-MM-DD HH:MM:SS (24-hour, Jakarta).");
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
      .slice(0, 90) || `Note #${note?.id}`
  );
}

function renderScopes() {
  const s = applied,
    out = [];
  const full = s.start === meta.start_ms && s.end === meta.end_ms;
  out.push(
    chip(`${shown(s.start)} → ${shown(s.end)} WIB`, {
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
      chip(`Note #${s.annotation_id}: ${note ? noteTitle(note) : "deleted"}`, {
        kind: "note",
        title: "Events linked to this note. Click to show it in Findings.",
        onClick: () => showNotes([s.annotation_id]),
        onRemove: () => apply({ ...s, annotation_id: null }),
      }),
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
        onClick: () => findingsTab("detections"),
        onRemove: () => apply({ ...s, rules: s.rules.filter((r) => r !== id) }),
      }),
    );
  }
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
    start: local(applied.start) + "+07:00",
    end: local(applied.end) + "+07:00",
    search: $("command-search").value,
  };
}

function commandLayout(sheet) {
  commandSheet = sheet;
  ++commandRequest;
  ++sheetRequest;
  $("command-browser-panel").hidden = sheet;
  $("command-sheet-panel").hidden = !sheet;
  $("sheet-density-label").hidden = !sheet;
  $("command-sort").disabled = $("command-direction").disabled = sheet;
  $("command-detail-layout").setAttribute("aria-pressed", String(!sheet));
  $("command-sheet-layout").setAttribute("aria-pressed", String(sheet));
  loadCommands();
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
      ? shown(cell.getValue()) + " WIB"
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
      column("Requested (WIB)", "requested_ms", 150, {
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
      column("Code", "response_code", 72),
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
  commandsActive = commands;
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
      title.textContent = `${row.requested_ms === null ? "Unknown time" : shown(row.requested_ms)} WIB · ${row.status}`;
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

async function openCommand(key) {
  if (commandSheet) commandLayout(false);
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
            `Start: ${wibTime(detail.ExecutionStartDateTime)}\nEnd: ${wibTime(detail.ExecutionEndDateTime)}`,
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
      button.textContent = `${shown(Date.parse(event.event_time))} WIB · ${event.operation} · ${event.error || "No API error"}\n${event.identity} · ${event.source_ip}\n${event.event_id} · ${event.source}`;
      button.onclick = async () => {
        if (event.id !== null) await detail({ id: event.id });
        else {
          try {
            const data = await request("/api/ssm-event", { key: event.key });
            detailRow = null;
            $("detail-id").textContent =
              `${data.event_id} · Supplemental SSM export (not in original DuckDB)`;
            $("detail-provenance").textContent =
              "Supplemental CloudTrail event, reconstructed from the SSM export JSON. Treat request/response contents as sensitive.";
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
  $("tags-tab").textContent = `Tags (${reviews.tags.length})`;
  $("notes-tab").textContent = `Notes (${reviews.annotations.length})`;
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
      : "No tags yet. Select events and use Quick tag.";
    items.push(li);
  }
  $("tag-list").replaceChildren(...items);
}

function showNotes(ids) {
  setFindings(true);
  findingsTab("notes");
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
      `Showing ${noteScope.length} note(s) on one event · `,
    );
    const all = document.createElement("button");
    all.className = "text-button";
    all.textContent = "Show all notes";
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
      info.textContent = `#${note.id} · ${number(note.events)} events · ${shown(Date.parse(note.updated)).slice(0, 16)} WIB`;
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
          "Filter to note",
          () => {
            if (commandsActive) switchView(false, false);
            apply({ ...applied, annotation_id: note.id });
          },
          "Add this note to the current query (AND)",
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
          "Whole export, only this note's events. Back restores your query.",
        );
        if (note.context)
          action(
            "Reopen query",
            () => {
              if (commandsActive) switchView(false, false);
              apply(note.context);
            },
            "Restore the query this note was written from",
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
            "Add the selected events that are not yet linked to this note",
          );
        if (onNote.length)
          action(
            `Unlink ${onNote.length} selected`,
            () =>
              writeReview({ action: "unlink", id: note.id, hashes: onNote }),
            "Remove the selected events from this note",
          );
        action("Edit", () => noteDialog(note));
        action("Delete", () => {
          if (
            confirm(
              `Delete note #${note.id} from all ${note.events} linked events?`,
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
      ? "No matching notes."
      : "No notes yet. Select events and use Add to note.";
    items.push(li);
  }
  $("note-list").replaceChildren(...items);
}

function setFindings(open) {
  document.querySelector(".layout").classList.toggle("no-findings", !open);
  $("findings").hidden = !open;
  $("toggle-findings").setAttribute("aria-pressed", String(open));
  localStorage.setItem("findings-open", open ? "1" : "0");
  requestAnimationFrame(() => {
    table?.redraw();
    if (lastHistogram) frequency(lastHistogram, lastContext);
    timeline();
    paintSelection();
  });
}

function findingsTab(which) {
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
      ". Detections are leads, not findings: tag or note what you confirm."
    : "";
}

async function loadDetections() {
  detections = await request("/api/detections");
  $("detections-tab").hidden = !detections.run;
  $("detections-tab").textContent = `Detections (${detections.rules.length})`;
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

function openNoteMenu(anchor) {
  $("note-menu-title").textContent =
    `${number(selectedEvents.size)} selected events`;
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
        b.title = "Link the selected events to this note";
        b.onclick = async () => {
          $("note-menu").hidePopover();
          await writeReview({
            action: "link",
            id: note.id,
            hashes: [...selectedEvents],
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
  if (s.annotation_id !== null) parts.push(`note #${s.annotation_id}`);
  for (const r of s.rules || [])
    parts.push(
      `Sigma ${detections.rules.find((d) => d.rule_id === r)?.title || r}`,
    );
  if (s.command_key !== null)
    parts.push(`SSM command ${s.command_label || ""}`);
  return parts.join(" · ");
}

function noteDialog(note = null) {
  editingNote = note; // Keeps `updated`: the server rejects edits to a note changed since.
  reviewHashes = [...selectedEvents];
  $("review-error").hidden = true;
  $("review-title").textContent = note
    ? `Edit note #${note.id} (${note.events} linked events)`
    : `New note on ${number(reviewHashes.length)} selected events`;
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
  if (!res.ok) throw new Error(result.error || `HTTP ${res.status}`);
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
    bar.style.opacity = ms + 86400000 > start && ms < end ? "1" : ".22";
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
  nlabel.textContent = "Notes";
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
      `${data.event_id} · ${row.time_local ? row.time_local + " WIB" : ""}`;
    $("detail-provenance").textContent =
      "Original DuckDB evidence JSON preserves numeric precision. Treat request/response contents as sensitive.";
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
    const ms = epoch(r.day + "T00:00:00"),
      height = (r.total / max) * 32;
    const bar = element("rect", {
      x: i * gap + 1,
      y: 34 - height,
      width: Math.max(1, gap - 2),
      height,
      class: "bar",
      "data-ms": ms,
      tabindex: 0,
      role: "button",
      "aria-label": `${r.day}: ${r.total} events; select this day`,
    });
    const title = document.createElementNS(svg.namespaceURI, "title");
    title.textContent = `${r.day}: ${number(r.total)} events; ${r.ssm} SSM commands/sessions`;
    bar.append(title);
    const choose = () => range(ms, ms + 86400000);
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
      ? new Map(context.data.map((r) => [r.bucket_start_local, r.events]))
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
      const c = ctx.get(row.bucket_start_local) || 0;
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
      "aria-label": `${row.bucket_start_local} WIB: ${row.events} events; narrow to this bucket`,
    });
    const title = document.createElementNS(svg.namespaceURI, "title");
    title.textContent =
      `${row.bucket_start_local} WIB: ${number(row.events)} selected events` +
      (ctx
        ? ` of ${number(ctx.get(row.bucket_start_local) || 0)} in context`
        : "") +
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
  const start = epoch(data.data[a].bucket_start_local.replace(" ", "T"));
  const end =
    epoch(data.data[b].bucket_start_local.replace(" ", "T")) +
    data.bucket_minutes * 60000;
  range(Math.max(start, applied.start), Math.min(end, applied.end));
}

// ---- Event grid ------------------------------------------------------------------------------
let tableReady = false;
function fitGrid() {
  if (!tableReady || commandsActive) return;
  const h = innerHeight - $("query-bar").offsetHeight - 6;
  table.setHeight(Math.max(260, h));
}

function tagCell(cell) {
  const d = cell.getRow().getData();
  const wrap = document.createElement("span");
  wrap.className = "tag-markers";
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
  if (!d.annotations.length) return "";
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
    `${d.annotations.length} notes; show in Findings`,
  );
  b.onclick = (e) => {
    e.stopPropagation();
    showNotes(d.annotations);
  };
  return b;
}

async function init() {
  meta = await request("/api/meta");
  applied = normalize({});
  queryHistory.push(applied);
  historyPos = 0;
  setFindings(localStorage.getItem("findings-open") !== "0");
  $("toggle-findings").onclick = () =>
    setFindings($("toggle-findings").getAttribute("aria-pressed") !== "true");
  $("close-findings").onclick = () => setFindings(false);
  $("tags-tab").onclick = () => findingsTab("tags");
  $("notes-tab").onclick = () => findingsTab("notes");
  $("detections-tab").onclick = () => findingsTab("detections");
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
    loadCommands();
  };
  $("more-commands").onclick = () => loadCommands(true);
  $("command-detail-layout").onclick = () => commandLayout(false);
  $("command-sheet-layout").onclick = () => commandLayout(true);
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
    noteDialog();
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
    `${number(meta.total)} events · ${local(meta.start_ms).slice(0, 10)} to ${local(meta.end_ms).slice(0, 10)} WIB`;
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
    $("start").value = shown(Number(values[0]));
    $("end").value = shown(Number(values[1]));
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
        title: "Notes",
        field: "annotations",
        width: 54,
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
      textColumn("Time (WIB)", "time_local", 150),
      textColumn("Operation", "event_name", 180),
      textColumn("AWS service", "event_source", 170),
      textColumn("Identity", "identity", 330),
      textColumn("Source IP", "source_ip", 130),
      textColumn("Country", "country", 120),
      textColumn("City", "city", 120, { visible: !!meta.enrichment }),
      textColumn("ASN", "asn", 90, { visible: !!meta.enrichment }),
      textColumn("Target", "target", 220),
      textColumn("Error", "error_code", 150),
      textColumn("Access key ID", "key_id", 190, { visible: false }),
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
      textColumn("Event ID", "event_id", 290),
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
init().catch((e) => error(e.message));
