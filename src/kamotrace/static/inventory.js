(() => {
  "use strict";
  const $ = (id) => document.getElementById(`inventory-${id}`);
  const list = (value) => (Array.isArray(value) ? value : []);
  const str = (value) =>
    value == null
      ? ""
      : typeof value === "object"
        ? JSON.stringify(value)
        : String(value);
  const display = (value) =>
    value == null || value === ""
      ? "Not recorded"
      : Array.isArray(value)
        ? value.length
          ? value.map(str).join(", ")
          : "None recorded"
        : str(value);
  const el = (tag, text, cls) => {
    const node = document.createElement(tag);
    if (text != null) node.textContent = text;
    if (cls) node.className = cls;
    return node;
  };
  const svgEl = (tag, attrs = {}, text) => {
    const node = document.createElementNS("http://www.w3.org/2000/svg", tag);
    Object.entries(attrs).forEach(([key, value]) =>
      node.setAttribute(key, str(value)),
    );
    if (text != null) node.textContent = text;
    return node;
  };
  let data = null,
    pending = null,
    view = "map",
    filtered = [],
    zoom = 1,
    world = { width: 1000, height: 500 },
    selected = null;
  const tables = new Map();
  const readyTables = new WeakSet();
  const statuses = ["Allowed", "Restricted", "Blocked", "Unknown", "Inactive"];
  const statusOf = (r) => (statuses.includes(r.status) ? r.status : "Unknown");
  const refId = (value) =>
    value && typeof value === "object"
      ? str(value.id || value.GroupId || value.group_id)
      : str(value);
  const attached = (g, r) =>
    str(g.region) === str(r.region) &&
    (list(r.security_groups).some((ref) => refId(ref) === str(g.id)) ||
      list(g.resources).some((ref) => refId(ref) === str(r.id)));
  const related = (p, r) =>
    (str(p.region) === str(r.region) &&
      str(p.load_balancer_id) === str(r.id)) ||
    (str(p.target_resource_region || p.region) === str(r.region) &&
      !!p.target_resource_id &&
      str(p.target_resource_id) === str(r.id));
  const routesFor = (r) =>
    list(data.forwarding_paths).filter((p) => related(p, r));
  const title = (r) =>
    str(
      r.name ||
        r.load_balancer_name ||
        r.id ||
        r.load_balancer_id ||
        "Collected record",
    );
  const searchable = (r, q) =>
    !q || JSON.stringify(r).toLowerCase().includes(q);
  const clip = (value, max = 34) =>
    str(value).length > max ? str(value).slice(0, max - 1) + "…" : str(value);
  function facts(host, entries) {
    const dl = el("dl", null, "inventory-facts");
    entries.forEach(([label, value]) => {
      const row = el("div");
      row.append(el("dt", label), el("dd", display(value)));
      dl.append(row);
    });
    host.append(dl);
  }
  function raw(host, heading, value, open = false) {
    const details = el("details");
    details.open = open;
    details.append(
      el("summary", heading),
      el("pre", JSON.stringify(value ?? null, null, 2)),
    );
    host.append(details);
  }
  function link(host, label, action) {
    const button = el("button", label, "inventory-link");
    button.type = "button";
    button.addEventListener("click", action);
    host.append(button);
  }
  function activate(node, action) {
    node.addEventListener("click", action);
    node.addEventListener("keydown", (event) => {
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        action();
      }
    });
  }
  async function selectResource(resource) {
    if (!data?.loaded) await show();
    if (data?.loaded && resource) inspect("resource", resource);
  }
  function inspect(kind, item) {
    selected = item;
    const host = $("evidence");
    host.replaceChildren(el("h3", title(item)));
    if (kind === "resource") {
      facts(host, [
        ["Kind / status", `${display(item.kind)} / ${statusOf(item)}`],
        ["ID", item.id],
        [
          "Region / account",
          `${display(item.region)} / ${display(item.account || data.metadata?.account)}`,
        ],
        [
          "VPC / subnets",
          `${display(item.vpc_id)} / ${display(item.subnet_ids)}`,
        ],
        ["State", item.state],
        ["Addresses", item.addresses],
        ["Direct assessment", item.direct_status],
        ["Via load balancer", item.indirect_status],
        ["Load balancers", item.via_load_balancers],
        ["IAM lookup status", item.iam_role_status],
        ["IAM roles", item.iam_roles],
        ["Role ARNs", item.iam_role_arns],
        ["Instance profile", item.iam_instance_profile],
        ["Assessment", item.summary],
      ]);
      host.append(el("h3", "Security groups"));
      list(data.security_groups)
        .filter((g) => attached(g, item))
        .forEach((g) =>
          link(host, `${title(g)} (${g.id})`, () => inspect("group", g)),
        );
      list(item.security_groups)
        .filter(
          (ref) =>
            !list(data.security_groups).some(
              (g) =>
                str(g.region) === str(item.region) && str(g.id) === refId(ref),
            ),
        )
        .forEach((ref) =>
          host.append(
            el("p", `${refId(ref)} — group evidence not collected`, "hint"),
          ),
        );
      if (!list(item.security_groups).length)
        host.append(
          el(
            "p",
            "No security group references recorded; not a safety assessment.",
            "hint",
          ),
        );
      host.append(el("h3", "Load balancer paths"));
      routesFor(item).forEach((p) =>
        link(
          host,
          `${display(p.listener_protocol)} :${display(p.listener_port)} → ${display(p.target_name || p.target_id)}:${display(p.target_port)} · ${display(p.status)}`,
          () => inspect("route", p),
        ),
      );
      raw(
        host,
        "Direct paths: security groups, routes and ACLs",
        item.paths || [],
        true,
      );
      raw(
        host,
        "Declared relationships",
        list(data.relationships).filter(
          (r) =>
            str(r.source) === str(item.id) || str(r.target) === str(item.id),
        ),
      );
      raw(host, "Inventory details", item.details);
    } else if (kind === "group") {
      facts(host, [
        ["ID", item.id],
        ["Region", item.region],
        ["VPC", item.vpc_id],
      ]);
      host.append(
        el("p", "Rules alone do not prove a complete internet path.", "hint"),
      );
      raw(host, "Ingress rules", item.ingress || [], true);
      raw(host, "Egress rules", item.egress || []);
      list(data.resources)
        .filter((r) => attached(item, r))
        .forEach((r) => link(host, title(r), () => selectResource(r)));
    } else if (kind === "route") {
      host.append(
        el(
          "p",
          "Configured potential match, not successful access. Priority, conditions, authentication and target health still apply.",
          "inventory-warning",
        ),
      );
      facts(host, [
        [
          "Status / reason",
          `${display(item.status)} / ${display(item.reason)}`,
        ],
        [
          "Region / scheme",
          `${display(item.region)} / ${display(item.scheme)}`,
        ],
        [
          "Listener / target port",
          `${display(item.listener_protocol)} :${display(item.listener_port)} → ${display(item.target_port)}`,
        ],
        [
          "Rule / priority",
          `${display(item.rule_id)} / ${display(item.priority)}`,
        ],
        ["Conditions", item.conditions],
        ["Actions", item.actions],
        ["Target group", item.target_group_name || item.target_group_id],
        [
          "Weight / health",
          `${display(item.weight)} / ${display(item.health)}`,
        ],
        [
          "Frontend / network",
          `${display(item.frontend_status)} / ${display(item.network_status)}`,
        ],
      ]);
      for (const [label, id, region] of [
        ["Load balancer", item.load_balancer_id, item.region],
        [
          "Backend",
          item.target_resource_id,
          item.target_resource_region || item.region,
        ],
      ]) {
        const matches = list(data.resources).filter(
          (r) => !!id && str(r.id) === str(id) && str(r.region) === str(region),
        );
        if (matches.length === 1)
          link(host, `${label}: ${title(matches[0])}`, () =>
            selectResource(matches[0]),
          );
        else
          host.append(
            el(
              "p",
              `${label}: ${display(id)} — resource evidence unavailable`,
              "hint",
            ),
          );
      }
      raw(host, "Network evidence", item.network_evidence, true);
    }
    raw(host, "Complete collected record", item);
    $("inspector").focus({ preventScroll: true });
    $("topology")
      .querySelectorAll(".inventory-node")
      .forEach((node) =>
        node.setAttribute(
          "aria-pressed",
          node.dataset.key === resourceKey(item) ? "true" : "false",
        ),
      );
  }
  function resourceKey(r) {
    return JSON.stringify([r.region, r.id]);
  }
  function table(id, rows, columns, kind) {
    const host = $(id);
    host.classList.add("inventory-table");
    if (tables.has(id)) {
      tables.get(id).replaceData(rows);
      return;
    }
    const grid = new Tabulator(host, {
      data: rows,
      layout: "fitDataStretch",
      height: "520px",
      placeholder:
        "No matching collected records. Clear filters or review coverage.",
      columnDefaults: {
        formatter: (cell) => el("span", display(cell.getValue())),
        headerSort: true,
        minWidth: 110,
      },
      columns: [
        {
          title: "Inspect",
          width: 80,
          headerSort: false,
          formatter: (cell) => {
            const button = el("button", "Inspect");
            button.type = "button";
            button.setAttribute(
              "aria-label",
              `Inspect ${title(cell.getRow().getData())}`,
            );
            button.addEventListener("click", () =>
              inspect(kind, cell.getRow().getData()),
            );
            return button;
          },
        },
        ...columns.map(([field, heading]) => ({ field, title: heading })),
      ],
    });
    tables.set(id, grid);
    grid.on("tableBuilt", () => readyTables.add(grid));
    grid.on("rowClick", (_event, row) => inspect(kind, row.getData()));
  }
  function renderCoverage() {
    const host = $("coverage-view"),
      m = data.metadata || {},
      errors = list(data.errors);
    host.replaceChildren(
      el("h3", "Collection scope and limitations"),
      el(
        "p",
        "Full snapshot scope, independent of filters. Missing, denied or failed evidence is unknown, not empty. Current configuration is not historical incident-time state.",
        "hint",
      ),
    );
    facts(host, [
      ["Account", m.account],
      ["Started (UTC)", m.started_at_utc],
      ["Completed (UTC)", m.completed_at_utc],
      ["Regions requested", m.regions],
      [
        "Collected records",
        `${list(data.resources).length} systems, ${list(data.vpcs).length} VPCs, ${list(data.security_groups).length} security groups`,
      ],
      ["Collection errors", errors.length],
    ]);
    host.append(
      el("h3", `Collection errors / denied operations (${errors.length})`),
    );
    if (errors.length)
      errors.forEach((error) =>
        raw(
          host,
          `${display(error.region)} · ${display(error.operation)} — collection failed`,
          error,
          true,
        ),
      );
    else
      host.append(
        el(
          "p",
          "No collection errors recorded. This does not guarantee complete coverage.",
          "hint",
        ),
      );
    host.append(el("h3", "Limitations"));
    if (list(m.limitations).length) {
      const ul = el("ul");
      m.limitations.forEach((value) => ul.append(el("li", str(value))));
      host.append(ul);
    } else
      host.append(
        el(
          "p",
          "No collector-specific limitations recorded; this is not a guarantee of complete analysis.",
          "hint",
        ),
      );
    host.append(
      el("h3", "VPC inventory"),
      el(
        "p",
        "VPCs with zero collected systems are not necessarily empty. Only services covered by this collector are represented.",
        "hint",
      ),
    );
    list(data.vpcs).forEach((vpc) =>
      raw(
        host,
        `${display(vpc.region)} / ${display(vpc.name || vpc.id)} · ${list(data.resources).filter((r) => str(r.region) === str(vpc.region) && str(r.vpc_id) === str(vpc.id)).length} systems collected`,
        vpc,
      ),
    );
    raw(host, "Snapshot metadata", m);
  }
  function render() {
    if (!data?.loaded) return;
    const q = $("search").value.trim().toLowerCase(),
      region = $("region").value,
      kind = $("kind").value,
      status = $("assessment").value;
    const scope = (r) =>
      (!region || str(r.region) === region) &&
      (!kind || str(r.kind) === kind) &&
      (!status || statusOf(r) === status);
    // Do not let a match in one embedded forwarding path match every path on its LB.
    const resourceMatches = (r) =>
      searchable({ ...r, forwarding_paths: undefined }, q);
    filtered = list(data.resources).filter(
      (r) =>
        scope(r) &&
        (resourceMatches(r) || routesFor(r).some((p) => searchable(p, q))),
    );
    $("count").textContent =
      `${filtered.length} of ${list(data.resources).length} collected systems · ${statuses.map((s) => `${s}: ${filtered.filter((r) => statusOf(r) === s).length}`).join(" · ")}`;
    const groups = list(data.security_groups).filter(
      (g) =>
        (!region || str(g.region) === region) &&
        searchable(g, q) &&
        (!(kind || status) ||
          list(data.resources).some((r) => scope(r) && attached(g, r))),
    );
    const routes = list(data.forwarding_paths).filter(
      (p) =>
        (!region || str(p.region) === region) &&
        (searchable(p, q) ||
          list(data.resources).some(
            (r) => scope(r) && resourceMatches(r) && related(p, r),
          )) &&
        (!(kind || status) ||
          list(data.resources).some((r) => scope(r) && related(p, r))),
    );
    const actions = list(data.listener_actions).filter(
      (p) =>
        (!region || str(p.region) === region) &&
        searchable(p, q) &&
        (!(kind || status) ||
          list(data.resources).some((r) => scope(r) && related(p, r))),
    );
    if (view === "map") renderMap();
    if (view === "systems")
      table(
        "systems-table",
        filtered,
        [
          ["name", "Name"],
          ["id", "ID"],
          ["kind", "Kind"],
          ["region", "Region"],
          ["vpc_id", "VPC"],
          ["status", "Assessment"],
          ["direct_status", "Direct"],
          ["indirect_status", "Via LB"],
          ["addresses", "Addresses"],
          ["iam_role_status", "IAM lookup"],
          ["iam_roles", "IAM roles"],
          ["summary", "Summary"],
        ],
        "resource",
      );
    if (view === "groups")
      table(
        "groups-table",
        groups,
        [
          ["name", "Group"],
          ["id", "ID"],
          ["region", "Region"],
          ["vpc_id", "VPC"],
          ["ingress", "Ingress"],
          ["egress", "Egress"],
        ],
        "group",
      );
    if (view === "routes") {
      table(
        "routes-table",
        routes,
        [
          ["load_balancer_name", "Load balancer"],
          ["region", "Region"],
          ["listener_port", "Listener port"],
          ["conditions", "Conditions"],
          ["target_name", "Backend"],
          ["target_port", "Target port"],
          ["status", "Status"],
          ["network_status", "Network"],
          ["reason", "Reason"],
        ],
        "route",
      );
      table(
        "actions-table",
        actions,
        [
          ["load_balancer_name", "Load balancer"],
          ["region", "Region"],
          ["listener_port", "Listener port"],
          ["priority", "Priority"],
          ["actions", "Actions"],
        ],
        "action",
      );
    }
  }
  function renderMap() {
    const svg = $("topology");
    svg.replaceChildren();
    const grouped = new Map(),
      positions = new Map();
    [...filtered]
      .sort(
        (a, b) =>
          str(a.region).localeCompare(str(b.region)) ||
          str(a.vpc_id).localeCompare(str(b.vpc_id)) ||
          title(a).localeCompare(title(b)),
      )
      .forEach((r) => {
        const key = JSON.stringify([r.region, r.vpc_id]);
        if (!grouped.has(key)) grouped.set(key, []);
        grouped.get(key).push(r);
      });
    let y = 18;
    grouped.forEach((resources) => {
      const height = 52 + Math.ceil(resources.length / 3) * 112;
      svg.append(
        svgEl("rect", {
          x: 12,
          y,
          width: 960,
          height,
          rx: 4,
          class: "inventory-vpc",
        }),
      );
      svg.append(
        svgEl(
          "text",
          { x: 28, y: y + 26 },
          `${display(resources[0].region)} / ${display(resources[0].vpc_id)}`,
        ),
      );
      resources.forEach((r, i) =>
        positions.set(r, {
          x: 32 + (i % 3) * 312,
          y: y + 44 + Math.floor(i / 3) * 112,
        }),
      );
      y += height + 20;
    });
    const edges = svgEl("g"),
      nodes = svgEl("g");
    svg.append(edges, nodes);
    const unique = (id, region) => {
      const matches = [...positions.keys()].filter(
        (r) =>
          !!id &&
          str(r.id) === str(id) &&
          (!region || str(r.region) === str(region)),
      );
      return matches.length === 1 ? matches[0] : null;
    };
    const edge = (a, b, record, forwarding) => {
      if (!a || !b) return;
      const pa = positions.get(a),
        pb = positions.get(b),
        startX = pa.x + 270,
        endX = pb.x;
      const routeY = Math.max(pa.y, pb.y) + 98;
      const path = svgEl("path", {
        d: `M${startX} ${pa.y + 43} H${startX + 10} V${routeY} H${endX - 10} V${pb.y + 43} H${endX}`,
        class: `inventory-edge${forwarding ? " forwarding" : ""}`,
        tabindex: 0,
        role: "button",
        "aria-label": `${forwarding ? "Load balancer path" : "Relationship"}: ${title(a)} to ${title(b)}. Inspect evidence.`,
      });
      path.append(
        svgEl(
          "title",
          {},
          display(record.label || record.reason || record.status),
        ),
      );
      activate(path, () =>
        inspect(forwarding ? "route" : "relationship", record),
      );
      edges.append(path);
    };
    list(data.relationships)
      .filter((r) => r.type !== "forwarding")
      .forEach((r) =>
        edge(
          unique(r.source, r.region),
          unique(r.target, r.target_region || r.region),
          r,
          false,
        ),
      );
    list(data.forwarding_paths).forEach((p) =>
      edge(
        unique(p.load_balancer_id, p.region),
        unique(p.target_resource_id, p.target_resource_region || p.region),
        p,
        true,
      ),
    );
    positions.forEach((p, r) => {
      const node = svgEl("g", {
        transform: `translate(${p.x} ${p.y})`,
        class: "inventory-node",
        tabindex: 0,
        role: "button",
        "aria-label": `${title(r)}, ${display(r.kind)}, ${statusOf(r)}. Inspect evidence.`,
        "aria-pressed": selected === r ? "true" : "false",
      });
      node.dataset.key = resourceKey(r);
      node.append(
        svgEl(
          "title",
          {},
          `${title(r)}\n${display(r.id)}\n${display(r.summary)}`,
        ),
        svgEl("rect", { width: 270, height: 88, rx: 3 }),
        svgEl("text", { x: 12, y: 20 }, clip(title(r))),
        svgEl(
          "text",
          { x: 12, y: 39, class: "inventory-node-sub" },
          clip(r.id),
        ),
        svgEl(
          "text",
          { x: 12, y: 58, class: "inventory-node-sub" },
          `${display(r.kind)} · ${statusOf(r)}`,
        ),
        svgEl(
          "text",
          { x: 12, y: 76, class: "inventory-node-sub" },
          clip(display(r.addresses)),
        ),
      );
      activate(node, () => selectResource(r));
      nodes.append(node);
    });
    if (!filtered.length)
      svg.append(
        svgEl(
          "text",
          { x: 24, y: 48 },
          "No matching collected systems. Clear filters or review coverage.",
        ),
      );
    world = { width: 990, height: Math.max(160, y) };
    resizeMap();
  }
  function resizeMap() {
    const svg = $("topology");
    svg.setAttribute("viewBox", `0 0 ${world.width} ${world.height}`);
    svg.setAttribute("width", world.width * zoom);
    svg.setAttribute("height", world.height * zoom);
    $("zoom").textContent = `${Math.round(zoom * 100)}%`;
  }
  function fitMap() {
    zoom = Math.max(
      0.3,
      Math.min(1, ($("canvas").clientWidth - 18) / world.width),
    );
    resizeMap();
  }
  function setView(next) {
    view = next;
    $("views")
      .querySelectorAll("button")
      .forEach((b) =>
        b.setAttribute("aria-pressed", String(b.dataset.view === view)),
      );
    ["map", "systems", "routes", "groups", "coverage"].forEach(
      (key) => ($(`${key}-view`).hidden = key !== view),
    );
    render();
    redrawTables();
  }
  function redrawTables() {
    tables.forEach((grid, id) => {
      if (readyTables.has(grid) && $(id).offsetWidth) grid.redraw(true);
    });
  }
  function options(id, values) {
    [...new Set(values.filter(Boolean).map(str))].sort().forEach((value) => {
      const option = el("option", value);
      option.value = value;
      $(id).append(option);
    });
  }
  async function load() {
    $("status").textContent = "Loading local inventory snapshot…";
    $("retry").hidden = true;
    try {
      const response = await fetch("/api/inventory", {
        headers: { Accept: "application/json" },
      });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const report = await response.json();
      if (!report || typeof report.loaded !== "boolean")
        throw new Error("Invalid inventory response");
      data = report;
      if (!data.loaded) {
        $("status").textContent =
          "No inventory snapshot loaded. Collect one with kamotrace inventory --output FOLDER, then restart with kamotrace serve --database CASE.duckdb --inventory-export FOLDER. CloudTrail events remain available in their own tab.";
        return;
      }
      $("status").textContent =
        "Configuration snapshot, not a live availability test. Coverage failures are not evidence of safety.";
      const m = data.metadata || {};
      $("metadata").textContent =
        `Account: ${display(m.account)} · Collection started (UTC): ${display(m.started_at_utc)} · Completed (UTC): ${display(m.completed_at_utc)}`;
      const errors = list(data.errors).length,
        limitations = list(m.limitations).length;
      $("warning").hidden = !(errors || limitations || !m.completed_at_utc);
      $("warning").textContent =
        `${errors} collection error(s) / denied operations; ${limitations} limitation(s). ${!m.completed_at_utc ? "Completion is not recorded. " : ""}Review Coverage before drawing conclusions; denied or failed is unknown, not absent.`;
      options("region", [
        ...list(m.regions),
        ...list(data.resources).map((r) => r.region),
        ...list(data.security_groups).map((r) => r.region),
        ...list(data.vpcs).map((r) => r.region),
        ...list(data.forwarding_paths).map((r) => r.region),
        ...list(data.listener_actions).map((r) => r.region),
        ...list(data.errors).map((r) => r.region),
      ]);
      options(
        "kind",
        list(data.resources).map((r) => r.kind),
      );
      options("assessment", statuses);
      $("content").hidden = false;
      renderCoverage();
      render();
      fitMap();
    } catch (error) {
      data = null;
      $("status").textContent =
        `Inventory could not be loaded (${error.message}). Check the local snapshot configuration and retry. No event evidence was changed.`;
      $("retry").hidden = false;
    }
  }
  async function show() {
    $("panel").hidden = false;
    if (!data && !pending)
      pending = load().finally(() => {
        pending = null;
      });
    if (pending) await pending;
    if (!$("panel").hidden)
      requestAnimationFrame(() => {
        resizeMap();
        redrawTables();
      });
  }
  function hide() {
    $("panel").hidden = true;
  }
  $("filters").addEventListener("submit", (event) => {
    event.preventDefault();
    render();
  });
  let searchTimer;
  $("search").addEventListener("input", () => {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(render, 150);
  });
  ["region", "kind", "assessment"].forEach((id) =>
    $(id).addEventListener("change", render),
  );
  $("clear").addEventListener("click", () => {
    $("filters").reset();
    render();
  });
  $("views")
    .querySelectorAll("button")
    .forEach((b) => b.addEventListener("click", () => setView(b.dataset.view)));
  $("retry").addEventListener("click", show);
  $("deselect").addEventListener("click", () => {
    selected = null;
    $("evidence").replaceChildren(
      el(
        "p",
        "Select a system, security group or load balancer path to inspect collected evidence.",
        "hint",
      ),
    );
    render();
  });
  $("zoom-in").addEventListener("click", () => {
    zoom = Math.min(2, zoom + 0.15);
    resizeMap();
  });
  $("zoom-out").addEventListener("click", () => {
    zoom = Math.max(0.3, zoom - 0.15);
    resizeMap();
  });
  $("fit").addEventListener("click", fitMap);
  window.kamotraceInventory = { show, hide, selectResource };
})();
