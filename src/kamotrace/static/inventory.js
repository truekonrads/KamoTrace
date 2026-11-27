(() => {
  "use strict";
  const $ = (id) => document.getElementById(`inventory-${id}`);
  const params = new URLSearchParams(location.search);
  const popout = params.get("view") === "aws-map";
  const filterIds = ["search", "region", "kind", "assessment", "exposure"];
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
  // A configured public forwarding route is not proof of successful access.
  const viaPublic = (r) =>
    routesFor(r).some(
      (p) =>
        (p.scheme === "internet-facing" || p.public_entry) &&
        str(p.target_resource_region || p.region) === str(r.region) &&
        !!p.target_resource_id &&
        str(p.target_resource_id) === str(r.id),
    );
  const isLoadBalancer = (r) =>
    /load\s*balancer|^elb|^alb|^nlb/i.test(str(r.kind)) ||
    list(data.forwarding_paths).some(
      (p) =>
        str(p.region) === str(r.region) &&
        str(p.load_balancer_id) === str(r.id),
    );
  const serviceIcon = (r) =>
    `/vendor/aws-icons/${{ EC2: "ec2", RDS: "rds", Lambda: "lambda", "Load balancer": "elb" }[r.kind] || "resource"}.svg`;
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
  const isEks = (r) => str(r.kind).startsWith("EKS ");
  const stamp = (value) => {
    const date = new Date(value);
    return value && Number.isFinite(date.getTime())
      ? date.toISOString().replace("T", " ").replace(".000Z", " UTC")
      : display(value);
  };
  let componentScope = null;
  let openEvent = null;
  let podTimezone = () => "UTC",
    formatPodTime = stamp;
  function eksOperations(cluster) {
    return list(data.eks_coverage).filter(
      (op) =>
        op.region === cluster.region &&
        (op.parameters?.clusterName === cluster.details?.cluster_name ||
          (op.operation === "describe_cluster" &&
            op.parameters?.name === cluster.details?.cluster_name)),
    );
  }
  function operationStatus(host, op, cluster) {
    host.append(
      el(
        "p",
        `${display(op.operation)} · ${display(op.status)} · ${display(op.pages)} page(s)`,
        op.status === "retrieved" ? "hint" : "inventory-warning",
      ),
    );
    if (
      op.operation === "list_access_entries" &&
      op.status === "error" &&
      cluster?.details?.aws?.accessConfig?.authenticationMode ===
        "CONFIG_MAP" &&
      /InvalidRequestException/.test(str(op.error)) &&
      /authentication mode|API_AND_CONFIG_MAP|must be.*API/i.test(str(op.error))
    ) {
      host.append(
        el(
          "p",
          "ListAccessEntries is incompatible with this cluster’s configured CONFIG_MAP authentication mode. Access entries were not retrieved; this is not evidence of no access. ConfigMap contents and effective Kubernetes access are not assessed. No authentication change is required or recommended by this view.",
          "inventory-warning",
        ),
      );
    }
    raw(
      host,
      `${display(op.operation)} — retrieval details / original exception`,
      op,
    );
  }
  function eksAccess(host, cluster) {
    const pages = list(cluster.details?.observations);
    const operations = eksOperations(cluster);
    host.append(
      el("h3", "Cluster access entries and associated policies"),
      el(
        "p",
        "Configured AWS access references only; not effective access, ConfigMap/RBAC evaluation or historical permissions. Partial pages remain visible when retrieval fails.",
        "hint",
      ),
    );
    for (const [heading, names, renderRow] of [
      [
        "Access entries / policies",
        [
          "list_access_entries",
          "describe_access_entry",
          "list_associated_access_policies",
        ],
        (response, page) => {
          list(response.accessEntries).forEach((principal) =>
            facts(host, [["Principal ARN", principal]]),
          );
          if (response.accessEntry)
            facts(host, Object.entries(response.accessEntry));
          list(response.associatedAccessPolicies).forEach((policy) =>
            facts(host, [
              ["Principal ARN", page.parameters?.principalArn],
              ["Policy ARN", policy.policyArn],
              ["Configured access scope", policy.accessScope],
              ["Associated", stamp(policy.associatedAt)],
            ]),
          );
        },
      ],
      [
        "Pod Identity associations",
        ["list_pod_identity_associations", "describe_pod_identity_association"],
        (response) => {
          [
            ...list(response.associations),
            ...(response.association ? [response.association] : []),
          ].forEach((association) =>
            facts(host, [
              ["Association", association.associationId],
              ["Namespace", association.namespace],
              ["Service account", association.serviceAccount],
              [
                "Role ARN",
                association.roleArn ||
                  "Not in this response; see describe retrieval status",
              ],
              ["Association ARN", association.associationArn],
            ]),
          );
        },
      ],
    ]) {
      host.append(el("h4", heading));
      const ops = operations.filter((op) => names.includes(op.operation));
      if (!ops.length)
        host.append(
          el(
            "p",
            "Not collected / no operation status recorded. Not assessed.",
            "hint",
          ),
        );
      ops.forEach((op) => operationStatus(host, op, cluster));
      const matching = pages.filter((page) => names.includes(page.operation));
      matching.forEach((page) => {
        host.append(
          el(
            "p",
            `${page.operation} · acquired ${stamp(page.acquired_at)}`,
            "hint",
          ),
        );
        renderRow(page.response || {}, page);
        raw(host, "Source: original AWS API observation page", page);
      });
      if (!matching.length)
        host.append(
          el(
            "p",
            "No API response pages attached to this section; consult retrieval gaps above. Not an effective-access or absence finding.",
            "hint",
          ),
        );
    }
    raw(host, "EKS snapshot source", cluster.details?.source);
  }
  function relatedComponents(host, item) {
    const relationships = list(data.relationships).filter(
      (r) =>
        r.region === item.region &&
        (r.source === item.id || r.target === item.id),
    );
    const components = list(data.resources).filter(
      (r) =>
        r.region === item.region &&
        r.id !== item.id &&
        relationships.some(
          (edge) => edge.source === r.id || edge.target === r.id,
        ),
    );
    host.append(
      el("h3", "Related components"),
      el(
        "p",
        "Configured EKS components — not traffic or pod placement",
        "hint",
      ),
    );
    components.forEach((r) =>
      link(host, `${r.kind}: ${title(r)}`, () => selectResource(r)),
    );
    if (!components.length)
      host.append(
        el(
          "p",
          "No related component references recorded in this snapshot; collection may be incomplete.",
          "hint",
        ),
      );
    if (item.kind === "EKS cluster") {
      link(host, "Show configured components", () => {
        if (!componentScope)
          componentScope = {
            values: filterIds.map((id) => $(id).value),
            view,
            cluster: item,
            ids: new Set(),
          };
        componentScope.cluster = item;
        componentScope.ids = new Set([item, ...components].map(resourceKey));
        $("filters").reset();
        setView("systems");
      });
      link(host, "Pod observations (explicit search)", () => openPods(item));
    }
  }
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
    const heading = el("div", null, "inventory-resource-heading"),
      icon = el("img"),
      label = el("div");
    icon.src = serviceIcon(kind === "route" ? { kind: "Load balancer" } : item);
    icon.alt = "";
    label.append(
      el("h3", title(item)),
      el(
        "p",
        kind === "resource"
          ? display(item.kind)
          : kind === "route"
            ? "Load balancer forwarding"
            : "Collected configuration",
        "hint",
      ),
    );
    heading.append(icon, label);
    host.replaceChildren(heading);
    if (kind === "resource")
      host.append(
        el(
          "p",
          `Selected: ${display(item.kind)} · ${display(item.region)} · ${display(item.account || data.metadata?.account)}`,
          "inventory-selection-context",
        ),
      );
    if (kind === "iam") {
      if (item.identity && item.id) {
        const reference = el("span", item.id);
        window.kamotraceReference?.attach(reference, {
          kind: "identity",
          value: item.id,
          account: data.metadata?.account,
        });
        host.append(el("h3", "Identity reference"), reference);
      }
      if (item.identity)
        window.kamotraceReference.iamDetails(host, item.context, data.iam);
      else {
        window.kamotraceReference.renderIamReview(host, item.signals, data.iam);
        facts(host, [
          ["Collection", item.kind],
          ["ARN", item.id],
          ["Region", "global"],
          ["Created", item.record.CreateDate],
          ["Updated", item.record.UpdateDate],
        ]);
      }
      host.append(
        el(
          "p",
          item.awsManaged
            ? "AWS-managed policy metadata only. Policy documents were not collected."
            : item.identity
              ? "Current IAM configuration, not incident-time state or effective permissions. The identity reference opens the same context from event and identity fields."
              : "Customer-managed policy snapshot, including collected version documents. This is not an effective-permissions evaluation.",
          "hint",
        ),
      );
      raw(host, "Native IAM record", item.record);
    } else if (kind === "resource") {
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
        [isEks(item) ? "Configured state" : "State", item.state],
        [
          "Addresses",
          isEks(item) && !list(item.addresses).length
            ? "Not applicable / not collected for this component"
            : item.addresses,
        ],
        [
          "Direct assessment",
          isEks(item) ? "Exposure Unknown — not assessed" : item.direct_status,
        ],
        [
          "Via load balancer",
          isEks(item) ? "Unknown — not assessed" : item.indirect_status,
        ],
        [
          "Load balancers",
          isEks(item) ? "Not assessed" : item.via_load_balancers,
        ],
        ["IAM lookup status", item.iam_role_status],
        [
          "IAM roles",
          isEks(item) && !list(item.iam_roles).length
            ? "No role reference in this component response"
            : item.iam_roles,
        ],
        [
          "Role ARNs",
          isEks(item) && !list(item.iam_role_arns).length
            ? "Not recorded in this component response"
            : item.iam_role_arns,
        ],
        ...(!isEks(item)
          ? [["Instance profile", item.iam_instance_profile]]
          : []),
        ["Assessment", item.summary],
      ]);
      if (item.kind?.startsWith("EKS ")) {
        const aws = item.details?.aws || {},
          network = aws.resourcesVpcConfig || {};
        host.append(el("h3", "Current EKS configuration"));
        facts(host, [
          ["Observed (UTC)", stamp(item.observed_at)],
          ["Cluster", item.details?.cluster_name],
          ["Version", aws.version || aws.addonVersion],
          ...(item.kind === "EKS cluster"
            ? [
                ["Public endpoint configured", network.endpointPublicAccess],
                ["Private endpoint configured", network.endpointPrivateAccess],
                ["Public endpoint CIDRs", network.publicAccessCidrs],
                ["Authentication mode", aws.accessConfig?.authenticationMode],
                ["Auto Mode compute", aws.computeConfig?.enabled],
              ]
            : []),
        ]);
        host.append(
          el(
            "p",
            "AWS configuration only, not incident-time state, workload placement or verified network/effective access. Component VPC context comes from its cluster; configured subnets are not observed pod placement.",
            "hint",
          ),
        );
        relatedComponents(host, item);
        if (item.kind === "EKS cluster") eksAccess(host, item);
      }
      for (const arn of list(item.iam_role_arns)) {
        const reference = el("p", arn);
        window.kamotraceReference?.attach(reference, {
          kind: "identity",
          value: arn,
          account: data.metadata?.account,
          region: item.region,
        });
        host.append(reference);
      }
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
      if (isEks(item))
        host.append(
          el(
            "p",
            "Exposure Unknown — load balancer paths and direct network reachability have not been assessed for EKS.",
            "hint",
          ),
        );
      routesFor(item).forEach((p) =>
        link(
          host,
          `${display(p.listener_protocol)} :${display(p.listener_port)} → ${display(p.target_name || p.target_id)}:${display(p.target_port)} · ${display(p.status)}`,
          () => inspect("route", p),
        ),
      );
      raw(
        host,
        isEks(item)
          ? "Direct paths — not assessed (raw collected field)"
          : "Direct paths: security groups, routes and ACLs",
        item.paths || [],
        list(item.paths).length > 0,
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
    if (kind !== "iam") raw(host, "Complete collected record", item);
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
        formatter: (cell) => {
          const row = cell.getRow().getData(),
            field = cell.getField();
          let value = cell.getValue();
          if (isEks(row)) {
            if (["indirect_status", "direct_status"].includes(field))
              value = "Unknown — not assessed";
            if (field === "addresses" && !list(value).length)
              value = "Not applicable / not collected";
            if (field === "iam_roles" && !list(value).length)
              value = "Not recorded in component response";
          }
          return el("span", display(value));
        },
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
        ...columns.map(([field, heading, options = {}]) => ({
          field,
          title: heading,
          ...options,
        })),
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
      ...(m.eks
        ? [
            ["EKS started (UTC)", m.eks.started_at],
            ["EKS completed (UTC)", m.eks.finished_at],
            ["EKS regions", m.eks.regions],
          ]
        : []),
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
    if (m.eks) {
      host.append(el("h3", "EKS per-operation retrieval / gaps"));
      list(data.eks_coverage).forEach((op) => {
        const cluster = list(data.resources).find(
          (r) =>
            r.kind === "EKS cluster" &&
            r.region === op.region &&
            r.details?.cluster_name ===
              (op.parameters?.clusterName || op.parameters?.name),
        );
        host.append(
          el(
            "h4",
            `${display(op.region)} / ${display(op.parameters?.clusterName || op.parameters?.name || "regional scope")}`,
          ),
        );
        operationStatus(host, op, cluster);
      });
      raw(host, "EKS AWS API collection coverage", data.eks_coverage);
    }
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
    host.append(el("h3", "IAM coverage"));
    if (data.iam) {
      facts(host, [
        ["Started (UTC)", data.iam.started_at_utc],
        ["Completed (UTC)", data.iam.completed_at_utc],
        ["Errors / denials", list(data.iam.errors).length],
      ]);
      list(data.iam.errors).forEach((error) =>
        raw(host, "IAM collection error / denial", error, true),
      );
      link(host, "Browse IAM snapshot and limitations", () => setView("iam"));
    } else
      host.append(
        el("p", "No IAM snapshot was collected in this export.", "hint"),
      );
  }
  const iamCollections = [
    ["users", "Users", "UserName"],
    ["roles", "Roles", "RoleName"],
    ["groups", "IAM groups", "GroupName"],
    ["policies", "Customer-managed policies", "PolicyName"],
    [
      "aws_managed_policies",
      "AWS-managed policies (metadata only)",
      "PolicyName",
    ],
  ];
  function renderIam(q) {
    const host = $("iam-coverage"),
      iam = data.iam;
    host.replaceChildren(el("h3", "IAM snapshot coverage"));
    host.append(
      el(
        "p",
        "Search applies to IAM records. Network region, kind, assessment and exposure filters do not apply: IAM is global. Current configuration is not incident-time state or an effective-permissions evaluation. Missing, denied or failed collection is unknown, not absent. AWS-managed policy documents are not collected.",
        "hint",
      ),
    );
    if (!iam) {
      host.append(
        el(
          "p",
          "No IAM snapshot was collected in this export.",
          "inventory-empty",
        ),
      );
    } else {
      facts(host, [
        ["Started (UTC)", iam.started_at_utc],
        ["Completed (UTC)", iam.completed_at_utc],
        ["Errors / denials", list(iam.errors).length],
      ]);
      if (!iam.completed_at_utc)
        host.append(
          el(
            "p",
            "IAM collection completion is not recorded.",
            "inventory-warning",
          ),
        );
      list(iam.errors).forEach((error) =>
        raw(host, "IAM collection error / denial", error, true),
      );
    }
    const key = $("iam-collection").value;
    const [, label, nameField] = iamCollections.find(([name]) => name === key);
    if (!Array.isArray(iam?.[key]))
      host.append(
        el(
          "p",
          `${label} were not collected in this export. Collect a new snapshot to include them.`,
          "inventory-warning",
        ),
      );
    const records = list(iam?.[key]);
    const policies = [
      ...list(iam?.policies),
      ...list(iam?.aws_managed_policies).map((p) => ({
        ...p,
        aws_managed: true,
      })),
    ];
    const rows = records
      .map((record) => {
        const groups = list(iam.groups).filter((g) =>
          list(record.GroupList).includes(g.GroupName),
        );
        const context = {
          iam:
            key === "aws_managed_policies"
              ? { ...record, aws_managed: true }
              : record,
          iam_groups: groups,
          iam_members: list(iam.users).filter(
            (u) =>
              record.GroupName && list(u.GroupList).includes(record.GroupName),
          ),
          iam_policies: policies,
        };
        const signals = window.kamotraceReference.iamReview(context, iam);
        const review = signals.filter((s) => s.level === "review");
        const unknown = signals.filter((s) => s.level === "unknown");
        const activity = record.activity;
        const keys = list(activity?.access_keys);
        const policyCount = (owner) =>
          [
            ...list(owner.UserPolicyList),
            ...list(owner.RolePolicyList),
            ...list(owner.GroupPolicyList),
            ...list(owner.AttachedManagedPolicies),
          ].length;
        return {
          id: record.Arn,
          name: record[nameField],
          kind: label,
          identity: ["users", "roles", "groups"].includes(key),
          awsManaged: key === "aws_managed_policies",
          review:
            [
              ...new Set(review.map((s) => s.label)),
              ...(unknown.length
                ? [`${unknown.length} coverage / unknown signals`]
                : []),
            ].join("; ") ||
            "No signals from limited checks; not a safety assessment",
          activity: record.UserName
            ? `${activity ? `${keys.filter((k) => k.Status === "Active").length} active / ${keys.length} recorded keys${activity.access_keys_status === "collected" ? "" : " (incomplete)"}` : "Keys not collected"}; console: ${activity?.console_status === "collected" ? activity.password_last_used || "timestamp unreported" : "unknown / not collected"}`
            : record.RoleName
              ? `Last used: ${record.RoleLastUsed?.LastUsedDate || "unreported"}${record.RoleLastUsed?.Region ? ` (${record.RoleLastUsed.Region})` : ""}`
              : "Not applicable",
          mfa: record.UserName
            ? `${activity?.mfa_status === "collected" ? `${list(activity.mfa_devices).length} enrolled devices` : "Enrollment unknown / incomplete"}; ${activity?.login_profile_status === "collected" ? "console password present" : activity?.login_profile_status === "not_configured" ? "no console password" : "console password unknown"}`
            : "Not applicable",
          memberships: record.UserName
            ? list(record.GroupList).join(", ") || "None recorded"
            : record.GroupName
              ? `${context.iam_members.length} recorded members`
              : "Not applicable",
          policies: record.PolicyName
            ? `${record.DefaultVersionId || "Default version unknown"}${key === "aws_managed_policies" ? "; metadata only" : ""}`
            : `${policyCount(record)} direct; ${groups.reduce((n, g) => n + policyCount(g), 0)} from groups`,
          created: record.CreateDate,
          updated: record.UpdateDate,
          record,
          context,
          signals,
        };
      })
      .filter((row) =>
        searchable(
          {
            record: row.record,
            review: row.review,
            activity: row.activity,
            memberships: row.memberships,
          },
          q,
        ),
      );
    $("count").textContent =
      `${rows.length} of ${records.length} collected ${label.toLowerCase()} (global)`;
    table(
      "iam-table",
      rows,
      [
        ["name", "Name", { width: 170 }],
        ["review", "Review signals", { width: 280, variableHeight: true }],
        [
          "activity",
          "Credential / role activity",
          { width: 250, variableHeight: true },
        ],
        [
          "memberships",
          "Groups / members",
          { width: 180, variableHeight: true },
        ],
        ["mfa", "MFA / console password", { width: 210, variableHeight: true }],
        ["policies", "Policies / default version", { width: 180 }],
        ["id", "ARN"],
      ],
      "iam",
    );
  }
  function render() {
    if (!data?.loaded) return;
    $("component-context").hidden = !componentScope || view === "pods";
    if (componentScope)
      $("component-context-label").textContent =
        `Scope changed: ${title(componentScope.cluster)} — configured EKS components, not traffic or pod placement. Prior filters are saved; inventory filters now narrow this component scope.`;
    const q = $("search").value.trim().toLowerCase(),
      region = $("region").value,
      kind = $("kind").value,
      status = $("assessment").value,
      exposure = $("exposure").value;
    const scope = (r) =>
      (!componentScope || componentScope.ids.has(resourceKey(r))) &&
      (!region || str(r.region) === region) &&
      (!kind || str(r.kind) === kind) &&
      (!status || statusOf(r) === status) &&
      (!exposure || (exposure === "via" ? viaPublic(r) : !viaPublic(r)));
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
        (!(kind || status || exposure) ||
          list(data.resources).some((r) => scope(r) && attached(g, r))),
    );
    const routes = list(data.forwarding_paths).filter(
      (p) =>
        (!region || str(p.region) === region) &&
        (searchable(p, q) ||
          list(data.resources).some(
            (r) => scope(r) && resourceMatches(r) && related(p, r),
          )) &&
        (!(kind || status || exposure) ||
          list(data.resources).some((r) => scope(r) && related(p, r))),
    );
    const actions = list(data.listener_actions).filter(
      (p) =>
        (!region || str(p.region) === region) &&
        searchable(p, q) &&
        (!(kind || status || exposure) ||
          list(data.resources).some((r) => scope(r) && related(p, r))),
    );
    if (view === "iam") renderIam(q);
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
    const defs = svgEl("defs"),
      arrow = svgEl("marker", {
        id: "inventory-arrow",
        viewBox: "0 0 10 10",
        refX: 9,
        refY: 5,
        markerWidth: 5,
        markerHeight: 5,
        orient: "auto-start-reverse",
      });
    arrow.append(svgEl("path", { d: "M0 0 L10 5 L0 10 Z", fill: "#228a9c" }));
    defs.append(arrow);
    svg.append(defs);
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
      const balancers = resources.filter(isLoadBalancer),
        backends = resources.filter((r) => !isLoadBalancer(r)),
        rows = balancers.length
          ? Math.max(balancers.length, Math.ceil(backends.length / 2))
          : Math.ceil(resources.length / 3),
        height = 116 + rows * 132;
      svg.append(
        svgEl("rect", {
          x: 12,
          y,
          width: 960,
          height,
          rx: 10,
          class: "inventory-vpc",
        }),
      );
      const vpc = list(data.vpcs).find(
        (v) =>
          str(v.region) === str(resources[0].region) &&
          str(v.id) === str(resources[0].vpc_id),
      );
      svg.append(
        svgEl("image", {
          x: 28,
          y: y + 18,
          width: 30,
          height: 30,
          href: "/vendor/aws-icons/vpc.svg",
        }),
        svgEl(
          "text",
          { x: 70, y: y + 30, class: "inventory-vpc-title" },
          clip(display(vpc?.name || resources[0].vpc_id), 80),
        ),
        svgEl(
          "text",
          { x: 70, y: y + 48, class: "inventory-node-sub" },
          `${display(resources[0].region)} · ${display(resources[0].vpc_id)} · ${resources.length} collected system${resources.length === 1 ? "" : "s"}`,
        ),
      );
      const lane = (x, width, label) => {
        svg.append(
          svgEl("rect", {
            x,
            y: y + 66,
            width,
            height: height - 82,
            rx: 7,
            class: "inventory-lane",
          }),
          svgEl(
            "text",
            { x: x + 14, y: y + 89, class: "inventory-lane-title" },
            label,
          ),
        );
      };
      if (balancers.length) {
        lane(26, 296, `Load balancers (${balancers.length})`);
        lane(338, 620, `Systems (${backends.length})`);
        balancers.forEach((r, i) =>
          positions.set(r, { x: 40, y: y + 104 + i * 132 }),
        );
        backends.forEach((r, i) =>
          positions.set(r, {
            x: 352 + (i % 2) * 312,
            y: y + 104 + Math.floor(i / 2) * 132,
          }),
        );
      } else {
        lane(26, 932, `Systems (${resources.length})`);
        resources.forEach((r, i) =>
          positions.set(r, {
            x: 40 + (i % 3) * 312,
            y: y + 104 + Math.floor(i / 3) * 132,
          }),
        );
      }
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
        forward = pb.x > pa.x,
        startX = pa.x + (forward ? 268 : 134),
        startY = pa.y + (forward ? 54 : 110),
        endX = pb.x - (forward ? 4 : -134),
        endY = pb.y + (forward ? 54 : -4),
        routeY = Math.max(pa.y, pb.y) + 122;
      const path = svgEl("path", {
        d:
          forward && pb.x - pa.x > 400
            ? `M${startX} ${startY} C${startX + 16} ${startY} ${startX + 16} ${routeY} ${startX + 28} ${routeY} H${endX - 16} Q${endX - 4} ${routeY} ${endX - 4} ${routeY - 12} V${endY + 10} Q${endX - 4} ${endY} ${endX} ${endY}`
            : forward
              ? `M${startX} ${startY} C${startX + 22} ${startY} ${endX - 22} ${endY} ${endX} ${endY}`
              : `M${startX} ${startY} C${startX} ${routeY} ${endX} ${routeY} ${endX} ${endY}`,
        class: `inventory-edge${forwarding ? " forwarding" : ""}`,
        "marker-end": forwarding ? "url(#inventory-arrow)" : "",
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
      node.dataset.status = statusOf(r);
      node.append(
        svgEl(
          "title",
          {},
          `${title(r)}\n${display(r.id)}\n${display(r.summary)}`,
        ),
        svgEl("rect", { width: 268, height: 110, rx: 7 }),
        svgEl("image", {
          x: 14,
          y: 14,
          width: 38,
          height: 38,
          href: serviceIcon(r),
          "aria-hidden": "true",
        }),
        svgEl(
          "text",
          { x: 64, y: 28, class: "inventory-node-title" },
          clip(title(r), 25),
        ),
        svgEl(
          "text",
          { x: 64, y: 46, class: "inventory-node-sub" },
          clip(r.id, 27),
        ),
        svgEl(
          "text",
          { x: 14, y: 73, class: "inventory-node-sub" },
          isEks(r) && !list(r.addresses).length
            ? "Configured component · exposure unknown"
            : clip(display(r.addresses), 38),
        ),
        svgEl(
          "text",
          { x: 14, y: 96, class: "inventory-node-sub" },
          display(r.kind),
        ),
        svgEl("circle", {
          cx: 184,
          cy: 92,
          r: 4,
          class: "inventory-status-dot",
        }),
        svgEl(
          "text",
          { x: 194, y: 96, class: "inventory-status-label" },
          statusOf(r),
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
    if (!$("canvas").clientWidth) return;
    setZoom(Math.min(1, ($("canvas").clientWidth - 18) / world.width), 0, 0);
    $("canvas").scrollTo(0, 0);
  }
  function setZoom(
    value,
    x = $("canvas").clientWidth / 2,
    y = $("canvas").clientHeight / 2,
  ) {
    const canvas = $("canvas"),
      previous = zoom,
      left = (canvas.scrollLeft + x) / previous,
      top = (canvas.scrollTop + y) / previous;
    zoom = Math.max(0.05, Math.min(3, value));
    resizeMap();
    canvas.scrollTo(left * zoom - x, top * zoom - y);
  }
  function setView(next) {
    if (view === "pods" && next !== "pods") ++podGeneration;
    view = next;
    $("panel").classList.toggle("inventory-pods-active", view === "pods");
    $("views")
      .querySelectorAll("button")
      .forEach((b) =>
        b.setAttribute("aria-pressed", String(b.dataset.view === view)),
      );
    ["map", "systems", "routes", "groups", "iam", "coverage", "pods"].forEach(
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
      const report = await request("/api/inventory");
      if (!report || typeof report.loaded !== "boolean")
        throw new Error("Invalid inventory response");
      data = report;
      if (!data.loaded) {
        $("status").textContent =
          "No inventory snapshot loaded. Collect one with kamotrace inventory --output FOLDER, then restart with kamotrace serve --database CASE.duckdb --inventory-export FOLDER. CloudTrail events remain available in their own tab.";
        return;
      }
      $("status").textContent =
        "Current configuration, not observed traffic. Coverage gaps are unknown.";
      const m = data.metadata || {};
      $("metadata").textContent =
        `Account: ${display(m.account)} · Collected: ${stamp(m.completed_at_utc)}` +
        (m.eks ? ` · EKS: ${stamp(m.eks.finished_at)}` : "");
      $("metadata").title =
        `Collection started (UTC): ${display(m.started_at_utc)}`;
      const errors = list(data.errors).length,
        limitations = list(m.limitations).length;
      $("warning").hidden = !(errors || limitations || !m.completed_at_utc);
      $("warning").replaceChildren(
        el(
          "span",
          `${errors} collection error(s) / denied operations; ${limitations} limitation(s). ${!m.completed_at_utc ? "Completion is not recorded. " : ""}Denied or failed is unknown, not absent.`,
        ),
      );
      link($("warning"), "Review coverage", () => setView("coverage"));
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
      $("open-explorer").hidden = false;
      if (popout)
        filterIds.forEach((id) => {
          $(id).value = params.get(id) || "";
        });
      renderCoverage();
      render();
      fitMap();
      if (popout) {
        const resource = list(data.resources).find(
          (r) =>
            str(r.id) === params.get("resource") &&
            str(r.region) === params.get("resource-region"),
        );
        if (resource) inspect("resource", resource);
      }
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
  // Historical pod observations stay separate from configuration-map nodes.
  const podView = el("section");
  podView.id = "inventory-pods-view";
  podView.hidden = true;
  podView.setAttribute("aria-label", "Historical EKS pod observations");
  $("coverage-view").before(podView);
  const componentContext = el("div", null, "inventory-warning");
  componentContext.id = "inventory-component-context";
  componentContext.hidden = true;
  const componentLabel = el("span");
  componentLabel.id = "inventory-component-context-label";
  componentContext.append(componentLabel);
  link(componentContext, "Return to prior filters / view", () => {
    const prior = componentScope;
    componentScope = null;
    if (prior) {
      filterIds.forEach((id, index) => {
        $(id).value = prior.values[index];
      });
      setView(prior.view);
      inspect("resource", prior.cluster);
    }
  });
  $("views").after(componentContext);
  let podGeneration = 0;
  function openPods(cluster) {
    ++podGeneration;
    const previousView = view === "pods" ? "systems" : view;
    const scope = {
      account: str(cluster.account || data.metadata?.account),
      region: str(cluster.region),
      cluster: str(cluster.details?.cluster_name || cluster.name),
    };
    const form = el("form", null, "inventory-toolbar"),
      inputs = {};
    form.id = "inventory-pods-filters";
    for (const [key, label, placeholder] of [
      [
        "start",
        `Start inclusive (ISO with offset; display ${podTimezone()})`,
        "2026-01-01T00:00:00Z",
      ],
      [
        "end",
        `End exclusive (ISO with offset; display ${podTimezone()})`,
        "2026-01-02T00:00:00Z",
      ],
      ["namespace", "Namespace (exact)", "All namespaces"],
      ["pod", "Pod name (exact)", "All names"],
      ["uid", "Pod UID (exact)", "All UIDs"],
    ]) {
      const labelNode = el("label", label),
        input = el("input");
      input.id = `inventory-pods-${key}`;
      input.placeholder = placeholder;
      input.autocomplete = "off";
      labelNode.append(input);
      inputs[key] = input;
      form.append(labelNode);
    }
    const submit = el("button", "Search attached pod observations");
    submit.type = "submit";
    form.append(submit);
    const state = el(
      "p",
      "Not searched — opening this view does not scan logs. Attached source coverage is checked only on explicit search.",
      "inventory-empty",
    );
    state.id = "inventory-pods-status";
    state.setAttribute("role", "status");
    const coverage = el("details"),
      results = el("div"),
      pager = el("div", null, "inventory-pod-pager");
    coverage.id = "inventory-pods-coverage";
    coverage.hidden = true;
    results.id = "inventory-pods-results";
    const warning = el(
      "p",
      "Historical observations, not current pod inventory. Authenticated caller is credential context, not the action target or current placement. Counts are observations, not requests; an API response does not prove runtime success.",
      "inventory-warning",
    );
    const back = el("div");
    link(back, "Back to selected cluster / prior inventory view", () => {
      ++podGeneration;
      setView(previousView);
      inspect("resource", cluster);
    });
    podView.replaceChildren(
      el("h3", `Historical pod observations · cluster “${scope.cluster}”`),
      el(
        "p",
        `${scope.account} / ${scope.region} · explicit historical search; inventory filters above do not constrain this view.`,
        "hint",
      ),
      back,
      warning,
      form,
      state,
      coverage,
      results,
    );
    setView("pods");
    let appliedScope = null;
    const invalidate = () => {
      ++podGeneration;
      appliedScope = null;
      results.replaceChildren();
      pager.replaceChildren();
      coverage.replaceChildren();
      coverage.hidden = true;
      state.textContent =
        "Not searched for current filters — prior results cleared. Run Search explicitly.";
    };
    Object.values(inputs).forEach((input) =>
      input.addEventListener("input", invalidate),
    );
    function prepareActivity(row) {
      inputs.namespace.value = row.namespace ?? "";
      inputs.pod.value = row.pod;
      inputs.uid.value = row.uid ?? "";
      invalidate();
      state.textContent = row.uid
        ? "Pod activity scope prepared — run Search explicitly."
        : "Name-scoped activity prepared — distinct pod instances may be included; run Search explicitly.";
      submit.focus();
    }
    async function search(page = 1, savedScope = null) {
      const generation = ++podGeneration;
      results.replaceChildren();
      coverage.replaceChildren();
      coverage.hidden = true;
      pager.replaceChildren();
      state.textContent =
        "Searching attached historical observations… prior results cleared.";
      try {
        const query = savedScope || { ...scope };
        if (!savedScope)
          for (const [key, input] of Object.entries(inputs)) {
            if (!input.value) continue;
            if (key === "start" || key === "end") {
              if (
                !/(Z|[+-]\d{2}:\d{2})$/.test(input.value) ||
                !Number.isFinite(Date.parse(input.value))
              )
                throw new Error(
                  `${key}: enter an ISO 8601 timestamp with explicit Z or numeric timezone offset`,
                );
              query[key] = new Date(input.value).toISOString();
            } else query[key] = input.value;
          }
        if (query.start && query.end && query.start >= query.end)
          throw new Error(
            "Start must be before end (start inclusive / end exclusive).",
          );
        const response = await request("/api/eks-pods", { ...query, page });
        if (generation !== podGeneration) return;
        if (response.searched !== true || !Array.isArray(response.data))
          throw new Error("Invalid pod observations response");
        appliedScope = query;
        const cov = response.coverage || {},
          datasets = list(cov.datasets);
        const gaps = datasets.flatMap((dataset) =>
          list(dataset.coverage_records).flatMap((record) =>
            list(record.manifest.operations).filter(
              (op) => op.status !== "retrieved",
            ),
          ),
        );
        coverage.hidden = false;
        coverage.open = false;
        const partial =
          gaps.length ||
          datasets.some((dataset) => !list(dataset.coverage_records).length);
        coverage.classList.toggle("inventory-pod-coverage-partial", !!partial);
        const coverageSummary = el("summary");
        coverageSummary.append(
          el(
            "strong",
            `${partial ? "Partial / unknown coverage" : "Source coverage — completeness not established"} · ${datasets.length} dataset(s) · ${gaps.length} operation gap(s)`,
          ),
          el("span", "Collection details", "inventory-pod-coverage-action"),
        );
        if (cov.first_log_time && cov.last_log_time)
          coverageSummary.append(
            el(
              "span",
              `Observed source extent: ${formatPodTime(cov.first_log_time)} → ${formatPodTime(cov.last_log_time)} · selected cluster / time bounds, not continuous coverage`,
              "inventory-pod-extent",
            ),
          );
        coverage.append(
          coverageSummary,
          el(
            "p",
            "Matching observations are not a complete pod history. Measured log extent is independent of namespace, pod and UID filters and is not the requested acquisition window or proof of complete logs.",
            "hint",
          ),
        );
        state.textContent = !datasets.length
          ? "Not collected — no attached EKS log sources in this scope. This does not mean no pods exist."
          : cov.log_events === 0
            ? "No collected log events reported for this scope — source datasets are attached, but pod activity is not established. Review manifests for uncollected, partial or failed log retrieval; this does not mean no pods exist."
            : response.total
              ? `${response.total} matching historical observations · page ${response.page} · newest first. Not current pod inventory.`
              : "No matching observations in the attached sources and selected bounds. This does not mean no pods exist; review collection coverage and gaps.";
        if (!query.uid)
          coverage.append(
            el(
              "p",
              "No UID scope: name-scoped observations may include distinct pod instances. Missing UID cannot establish pod identity.",
              "inventory-warning",
            ),
          );
        raw(coverage, "Applied historical search scope", response.scope);
        coverage.append(
          el(
            "h4",
            "Attached source coverage — independent of matching observations",
          ),
        );
        facts(coverage, [
          ["Datasets", datasets.length],
          ["Log events", cov.log_events],
          ["Pod observations", cov.pod_observations],
          ["Malformed messages", cov.malformed_messages],
          [
            "Messages without a supported named pod context",
            cov.unrecognized_messages,
          ],
          [
            "Unresolved cluster context (account / region, all times)",
            cov.unresolved_cluster_events,
          ],
        ]);
        list(cov.limitations).forEach((value) =>
          coverage.append(el("p", str(value), "inventory-warning")),
        );
        datasets.forEach((dataset) => {
          coverage.append(
            el(
              "h4",
              `Dataset ${dataset.dataset_index} · ${display(dataset.origin)}`,
            ),
          );
          facts(coverage, [
            ["Records", dataset.records],
            ["Source SHA256", dataset.source_sha256],
          ]);
          coverage.append(
            el(
              "p",
              list(dataset.coverage_records).length
                ? "Manifest collection scope and per-operation statuses below may be partial or failed; matching rows do not prove complete collection."
                : "No manifest attached — collection completeness unknown.",
              "hint",
            ),
          );
          list(dataset.coverage_records).forEach((record) => {
            const manifest = record.manifest;
            coverage.append(el("h5", `Coverage record ${record.id}`));
            facts(coverage, [
              ["Record SHA256", record.record_sha256],
              ["Record time (UTC)", stamp(record.time)],
            ]);
            if (openEvent)
              link(coverage, "Open original coverage event", () =>
                openEvent(record.id),
              );
            facts(coverage, [
              ["Started (UTC)", stamp(manifest.started_at)],
              ["Finished (UTC)", stamp(manifest.finished_at)],
              [
                "Status",
                manifest.status || "Not recorded; consult operation statuses",
              ],
              [
                "Settings / collection bounds",
                manifest.scope || manifest.settings,
              ],
            ]);
            list(manifest.limitations).forEach((value) =>
              coverage.append(el("p", str(value), "inventory-warning")),
            );
            list(manifest.warnings).forEach((value) =>
              coverage.append(el("p", str(value), "inventory-warning")),
            );
            list(manifest.operations).forEach((op) => {
              coverage.append(
                el(
                  "p",
                  `${display(op.region)} / ${display(op.operation)} · ${display(op.status)} · ${display(op.pages)} pages`,
                  op.status === "retrieved" ? "hint" : "inventory-warning",
                ),
              );
              raw(coverage, "Operation scope / retrieval details", op);
            });
          });
          raw(coverage, "Attached dataset and raw coverage manifests", dataset);
        });
        const identities = el("section", null, "inventory-pod-identities"),
          contextList = el("div", null, "inventory-pod-context-list"),
          activity = el("section", null, "inventory-pod-activity");
        identities.id = "inventory-pod-contexts";
        identities.setAttribute("aria-label", "Observed pod identity contexts");
        activity.setAttribute("aria-label", "Historical pod activity");
        identities.append(
          el("h4", `Identity contexts (${response.total_contexts ?? 0})`),
          el(
            "p",
            `Showing ${list(response.contexts).length} of ${response.total_contexts ?? 0} across the full filtered selection. Select an identity to prepare filters, then press Search.`,
            "hint",
          ),
          el(
            "p",
            "Roles and UIDs stay separate. Missing UIDs leave name reuse unresolved.",
            "hint",
          ),
          contextList,
        );
        list(response.contexts).forEach((context) => {
          const button = el("button", null, "inventory-pod-context");
          button.type = "button";
          button.setAttribute(
            "aria-label",
            `${context.observation_role} · ${display(context.namespace)} / ${context.pod} · UID ${display(context.uid)} · ${context.observations} observations`,
          );
          button.title = "Prepare activity filters; run Search explicitly";
          button.append(
            el("strong", context.observation_role, "inventory-pod-role"),
            el(
              "span",
              `${display(context.namespace)} / ${context.pod}`,
              "inventory-pod-name",
            ),
            el("span", `UID: ${display(context.uid)}`, "hint"),
            el(
              "span",
              `${context.observations} observations`,
              "inventory-pod-context-count",
            ),
            el(
              "span",
              `${formatPodTime(context.first_seen)} → ${formatPodTime(context.last_seen)}`,
              "hint",
            ),
          );
          button.addEventListener("click", () => prepareActivity(context));
          contextList.append(button);
        });
        activity.append(
          el("h4", "Activity"),
          el(
            "p",
            `${response.total} observations · page ${response.page} · newest first. All roles matching the applied filters are shown.`,
            "hint",
          ),
          pager,
        );
        results.append(identities, activity);
        const grid = el("table", null, "inventory-pod-table"),
          head = el("thead"),
          header = el("tr"),
          body = el("tbody");
        [
          `Time (${podTimezone()})`,
          "Identity / observation role",
          "Actor",
          "Action / target / subresource / stage",
          "Outcome / status",
          "Source / actions",
        ].forEach((label) => header.append(el("th", label)));
        head.append(header);
        list(response.data).forEach((row) => {
          const tr = el("tr"),
            identity = el("td"),
            source = el("td"),
            identityDetails = el("details");
          identityDetails.append(
            el("summary", "Identity details"),
            el("p", `Namespace basis: ${display(row.namespace_basis)}`, "hint"),
          );
          identity.append(
            el("strong", display(row.observation_role), "inventory-pod-role"),
            el("p", `${display(row.namespace)} / ${row.pod}`),
            el("p", `UID: ${display(row.uid)}`),
            identityDetails,
          );
          if (row.node || row.node_uid)
            identityDetails.append(
              el(
                "p",
                `Credential node context (not scheduled/current node): ${display(row.node)} · UID ${display(row.node_uid)}`,
                "hint",
              ),
            );
          if (!row.uid)
            identityDetails.append(
              el(
                "p",
                "UID missing — name scope may include distinct pod instances",
                "hint",
              ),
            );
          link(identityDetails, "View pod activity", () =>
            prepareActivity(row),
          );
          if (openEvent)
            link(source, "Open original source event", () => openEvent(row.id));
          else
            source.append(
              el(
                "p",
                "Original event detail is unavailable in this window; return to the main application.",
                "hint",
              ),
            );
          raw(source, "Source provenance", {
            record_sha256: row.record_sha256,
            dataset_index: row.dataset_index,
            source_type: row.source_type,
            ...row.source,
            cluster_basis: row.cluster_basis,
          });
          raw(source, "Derived observation details", {
            observation_role: row.observation_role,
            namespace_basis: row.namespace_basis,
            pod: row.pod,
            uid: row.uid,
            actor: row.actor,
            credential_node_context: { name: row.node, uid: row.node_uid },
            target_resource: row.target_resource,
            target_namespace: row.target_namespace,
            status_code: row.status_code,
            stage: row.stage,
            outcome: row.outcome,
          });
          tr.append(
            el("td", formatPodTime(row.time)),
            identity,
            el("td", display(row.actor)),
            el(
              "td",
              `${display(row.action)} / target ${display(row.target_resource)} in ${display(row.target_namespace)} / ${display(row.subresource)} / ${display(row.stage)}`,
            ),
            el("td", display(row.outcome)),
            source,
          );
          body.append(tr);
        });
        grid.append(head, body);
        const scroll = el("div", null, "inventory-pod-activity-scroll");
        scroll.append(grid);
        activity.append(scroll);
        if (response.page > 1)
          link(pager, "Previous page", () =>
            search(response.page - 1, appliedScope),
          );
        if (response.page * response.page_size < response.total)
          link(pager, "Next page", () =>
            search(response.page + 1, appliedScope),
          );
      } catch (error) {
        if (generation !== podGeneration) return;
        appliedScope = null;
        state.textContent = `Search failed — no current results. ${error.message}. Correct filters or retry Search; no absence conclusion is supported.`;
      }
    }
    form.addEventListener("submit", (event) => {
      event.preventDefault();
      search();
    });
  }
  // Keep this optional collection view self-contained; older exports remain usable.
  const iamButton = el("button", "IAM");
  iamButton.type = "button";
  iamButton.dataset.view = "iam";
  iamButton.setAttribute("aria-pressed", "false");
  $("views").append(iamButton);
  const iamView = el("section");
  iamView.id = "inventory-iam-view";
  iamView.hidden = true;
  iamView.setAttribute("aria-label", "Global IAM inventory");
  const iamLabel = el("label", "IAM collection ", "inventory-iam-selector");
  const iamSelect = el("select");
  iamSelect.id = "inventory-iam-collection";
  iamCollections.forEach(([key, label]) => {
    const option = el("option", label);
    option.value = key;
    iamSelect.append(option);
  });
  iamLabel.append(iamSelect);
  const iamCoverage = el("div");
  iamCoverage.id = "inventory-iam-coverage";
  const iamTable = el("div");
  iamTable.id = "inventory-iam-table";
  iamView.append(iamLabel, iamCoverage, iamTable);
  $("coverage-view").before(iamView);
  iamSelect.addEventListener("change", render);
  $("filters").addEventListener("submit", (event) => {
    event.preventDefault();
    render();
  });
  let searchTimer;
  $("search").addEventListener("input", () => {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(render, 150);
  });
  ["region", "kind", "assessment", "exposure"].forEach((id) =>
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
  $("zoom-in").addEventListener("click", () => setZoom(zoom * 1.2));
  $("zoom-out").addEventListener("click", () => setZoom(zoom / 1.2));
  $("fit").addEventListener("click", fitMap);
  $("pop-out").addEventListener("click", () => {
    const url = new URL(location.pathname, location.origin);
    url.searchParams.set("view", "aws-map");
    filterIds.forEach((id) => {
      if ($(id).value) url.searchParams.set(id, $(id).value);
    });
    if (selected && list(data?.resources).includes(selected)) {
      url.searchParams.set("resource", str(selected.id));
      url.searchParams.set("resource-region", str(selected.region));
    }
    window.open(url, "_blank", "noopener,noreferrer");
  });
  $("fit-all").addEventListener("click", () => {
    const canvas = $("canvas");
    setZoom(
      Math.min(
        (canvas.clientWidth - 18) / world.width,
        (canvas.clientHeight - 18) / world.height,
      ),
      0,
      0,
    );
    canvas.scrollTo(0, 0);
  });
  const canvas = $("canvas");
  canvas.addEventListener(
    "wheel",
    (event) => {
      if (!data?.loaded || !filtered.length) return;
      event.preventDefault();
      const rect = canvas.getBoundingClientRect();
      setZoom(
        zoom * Math.exp(-Math.max(-200, Math.min(200, event.deltaY)) * 0.002),
        event.clientX - rect.left,
        event.clientY - rect.top,
      );
    },
    { passive: false },
  );
  let drag = null;
  canvas.addEventListener("pointerdown", (event) => {
    const rect = canvas.getBoundingClientRect();
    if (
      event.button !== 0 ||
      event.target.closest(".inventory-node, .inventory-edge") ||
      event.clientX >= rect.left + canvas.clientWidth ||
      event.clientY >= rect.top + canvas.clientHeight
    )
      return;
    drag = {
      x: event.clientX,
      y: event.clientY,
      left: canvas.scrollLeft,
      top: canvas.scrollTop,
    };
    canvas.setPointerCapture(event.pointerId);
    canvas.classList.add("dragging");
  });
  canvas.addEventListener("pointermove", (event) => {
    if (drag)
      canvas.scrollTo(
        drag.left + drag.x - event.clientX,
        drag.top + drag.y - event.clientY,
      );
  });
  const stopDrag = () => {
    drag = null;
    canvas.classList.remove("dragging");
  };
  canvas.addEventListener("pointerup", stopDrag);
  canvas.addEventListener("lostpointercapture", stopDrag);
  canvas.addEventListener("keydown", (event) => {
    if (event.target !== canvas) return;
    if (["+", "=", "-", "Home"].includes(event.key)) {
      event.preventDefault();
      if (event.key === "Home") fitMap();
      else setZoom(event.key === "-" ? zoom / 1.2 : zoom * 1.2);
    }
  });
  const explorer = $("explorer"),
    panel = $("panel"),
    home = document.createComment("Inventory workspace home");
  panel.before(home);
  $("open-explorer").addEventListener("click", () => {
    explorer.append(panel);
    explorer.showModal();
    fitMap();
    redrawTables();
  });
  $("close-explorer").addEventListener("click", () => explorer.close());
  explorer.addEventListener("close", () => {
    home.after(panel);
    fitMap();
    redrawTables();
    $("open-explorer").focus({ preventScroll: true });
  });
  if (popout) {
    document.body.classList.add("inventory-popout");
    document.body.append(panel);
    $("fit-all").after($("clear"));
    document.title = "AWS map · KamoTrace";
  }
  window.kamotraceInventory = {
    show,
    hide,
    selectResource,
    popout,
    setEventOpener: (callback, timezone = "UTC", formatter = stamp) => {
      openEvent = callback;
      podTimezone = typeof timezone === "function" ? timezone : () => timezone;
      formatPodTime = formatter;
    },
  };
})();
