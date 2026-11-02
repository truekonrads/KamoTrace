/* Read-only reference context. Never inspect command output or raw evidence JSON. */
(() => {
  "use strict";
  const attached = new WeakSet();
  let active = null,
    sequence = 0,
    hoverTimer,
    closeTimer,
    restoringFocus = false;
  const card = document.createElement("section");
  card.id = "reference-card";
  card.className = "reference-card";
  card.hidden = true;
  card.tabIndex = -1;
  card.setAttribute("role", "region");
  card.setAttribute("aria-label", "Reference context");
  card.setAttribute("aria-live", "polite");
  // The popover top layer also works above the spreadsheet's modal dialog.
  card.setAttribute("popover", "manual");
  document.body.append(card);

  function close() {
    clearTimeout(hoverTimer);
    clearTimeout(closeTimer);
    sequence++;
    if (active) active.element.removeAttribute("aria-describedby");
    active = null;
    if (card.matches(":popover-open")) card.hidePopover();
    card.hidden = true;
  }

  function position() {
    if (!active || card.hidden) return;
    if (!active.element.isConnected) return close();
    const rect = active.element.getBoundingClientRect();
    const width = card.offsetWidth,
      height = card.offsetHeight;
    card.style.left = `${Math.max(8, Math.min(rect.left, innerWidth - width - 8))}px`;
    const below = rect.bottom + 6;
    card.style.top = `${Math.max(8, Math.min(below + height <= innerHeight - 8 ? below : rect.top - height - 6, innerHeight - height - 8))}px`;
  }

  function line(parent, tag, text, className = "") {
    const element = document.createElement(tag);
    element.className = className;
    element.textContent = String(text);
    parent.append(element);
    return element;
  }

  // Deliberate allowlist: never dump resource payloads, tags, credentials or command parameters.
  const fields = {
    id: "ID",
    name: "Name",
    arn: "ARN",
    instance_id: "Instance ID",
    instance_type: "Instance type",
    kind: "Resource type",
    state: "State",
    status: "Configuration assessment",
    summary: "Assessment scope",
    addresses: "Addresses / endpoints",
    security_groups: "Security groups",
    subnet_ids: "Subnets",
    iam_roles: "Assigned IAM roles",
    iam_role_status: "IAM lookup status",
    platform: "Platform",
    private_ip: "Private IP",
    public_ip: "Public IP",
    private_dns: "Private DNS",
    public_dns: "Public DNS",
    vpc_id: "VPC",
    subnet_id: "Subnet",
    cidr: "Matching CIDR",
    availability_zone: "Availability zone",
    image_id: "Image ID",
    ip: "IP",
    country: "Country",
    country_code: "Country code",
    city: "City",
    region: "Region",
    asn: "ASN",
    isp: "Network / ISP",
    organization: "Organization",
    identity_type: "Identity type",
    type: "Type",
    principal_id: "Principal ID",
    user_name: "User name",
    event_count: "Observed events",
    command_count: "Observed SSM commands",
    first_seen: "First seen",
    last_seen: "Last seen",
    source: "Source",
    provider: "Provider",
  };

  function details(parent, object) {
    if (!object || typeof object !== "object") return;
    const list = document.createElement("dl");
    for (const [key, label] of Object.entries(fields)) {
      const raw = object[key];
      const value =
        Array.isArray(raw) && raw.every((v) => typeof v === "string")
          ? raw.join(", ")
          : raw;
      if (
        value === null ||
        value === undefined ||
        value === "" ||
        typeof value === "object"
      )
        continue;
      line(list, "dt", label);
      line(list, "dd", value);
    }
    if (list.childElementCount) parent.append(list);
  }

  function policyDetails(parent, label, value) {
    const section = document.createElement("details");
    line(section, "summary", label);
    line(section, "pre", JSON.stringify(value ?? null, null, 2));
    parent.append(section);
  }

  function iamDetails(parent, match) {
    const iam = match.iam;
    if (!iam || typeof iam !== "object") return;
    const list = (value) => (Array.isArray(value) ? value : []);
    line(parent, "h3", "IAM configuration");
    details(parent, {
      name: iam.UserName || iam.RoleName || iam.GroupName,
      arn: iam.Arn,
      principal_id: iam.UserId || iam.RoleId || iam.GroupId,
    });
    const dates = document.createElement("dl");
    for (const [label, value] of [
      ["Created", iam.CreateDate],
      ["Password last used", iam.PasswordLastUsed],
      ["Role last used", iam.RoleLastUsed],
      ["Maximum session (seconds)", iam.MaxSessionDuration],
    ]) {
      if (value == null) continue;
      line(dates, "dt", label);
      line(
        dates,
        "dd",
        typeof value === "object" ? JSON.stringify(value) : value,
      );
    }
    parent.append(dates);
    if (iam.AssumeRolePolicyDocument != null)
      policyDetails(parent, "Trust policy", iam.AssumeRolePolicyDocument);

    function policies(host, identity) {
      const inline = [
        ...list(identity.UserPolicyList),
        ...list(identity.RolePolicyList),
        ...list(identity.GroupPolicyList),
      ];
      line(
        host,
        "p",
        `Inline policies: ${inline.length}`,
        "reference-provenance",
      );
      inline.forEach((policy) =>
        policyDetails(
          host,
          `Inline: ${policy.PolicyName || "Unnamed policy"}`,
          policy.PolicyDocument,
        ),
      );
      const attached = list(identity.AttachedManagedPolicies);
      line(
        host,
        "p",
        `Attached managed policies: ${attached.length}`,
        "reference-provenance",
      );
      attached.forEach((ref) => {
        const policy = list(match.iam_policies).find(
          (p) => p.Arn === ref.PolicyArn,
        );
        const type = policy
          ? policy.aws_managed
            ? "AWS managed; metadata only"
            : "Customer managed"
          : "Type / document not collected";
        policyDetails(
          host,
          `${ref.PolicyName || ref.PolicyArn} (${type})`,
          policy || ref,
        );
        if (!policy || policy.aws_managed)
          line(
            host,
            "p",
            "Policy document unavailable in this snapshot; permissions are unknown.",
            "reference-provenance",
          );
      });
      if (identity.PermissionsBoundary) {
        const boundary = identity.PermissionsBoundary;
        const policy = list(match.iam_policies).find(
          (p) => p.Arn === boundary.PermissionsBoundaryArn,
        );
        policyDetails(host, "Permissions boundary", {
          ...boundary,
          policy: policy || "Document not collected",
        });
      }
    }
    policies(parent, iam);
    if (iam.GroupName) {
      line(parent, "h3", "Collected group members");
      list(match.iam_members).forEach((user) =>
        line(parent, "p", `${user.UserName} · ${user.Arn}`),
      );
      if (!list(match.iam_members).length)
        line(
          parent,
          "p",
          "No members recorded; incomplete collection may omit members.",
          "reference-provenance",
        );
    }
    const groupNames = list(iam.GroupList);
    if (groupNames.length || list(match.iam_groups).length) {
      line(parent, "h3", "Group membership");
      groupNames.forEach((name) => line(parent, "p", name));
      list(match.iam_groups).forEach((group) => {
        const section = document.createElement("section");
        line(section, "h3", group.GroupName || group.Arn || "IAM group");
        details(section, { arn: group.Arn });
        policies(section, group);
        parent.append(section);
      });
      if (groupNames.length > list(match.iam_groups).length)
        line(
          parent,
          "p",
          "Some group configuration was not collected.",
          "reference-warning",
        );
    }
    line(
      parent,
      "p",
      "Current IAM snapshot, not incident-time state or an effective-permissions evaluation. Trust conditions, boundaries, session policies, resource policies and organization controls may restrict access. Missing or denied collection is unknown, not absence.",
      "reference-warning",
    );
    policyDetails(parent, "Collected IAM identity details", iam);
  }

  function reveal(data, message) {
    card.replaceChildren();
    const header = document.createElement("header");
    line(header, "strong", `${active.spec.kind} reference`);
    const dismiss = line(header, "button", "Close");
    dismiss.type = "button";
    dismiss.onclick = () => {
      const anchor = active?.element;
      close();
      restoringFocus = true;
      anchor?.focus({ preventScroll: true });
      restoringFocus = false;
    };
    header.append(dismiss);
    card.append(header);
    line(card, "p", active.spec.value, "reference-value");
    if (message) line(card, "p", message);
    if (data) {
      if (data.ambiguous)
        line(
          card,
          "p",
          `${data.matches.length} exact matches — separate candidates, not a resolved association.`,
          "reference-warning",
        );
      const matches = [...data.matches, ...(data.network_matches || [])];
      for (const match of matches) {
        const section = document.createElement("section");
        section.className = "reference-match";
        line(
          section,
          "h3",
          match.name || match.id || match.kind || "Exact match",
        );
        line(
          section,
          "p",
          `Source: ${match.source || "unknown"} · Account: ${match.account || "not supplied"} · Region: ${match.region || "not supplied"}`,
          "reference-provenance",
        );
        if (match.network)
          line(
            section,
            "p",
            "Network range match — address is within this CIDR; no resource ownership is established.",
            "reference-warning",
          );
        else if (data.kind === "ip" && match.source === "inventory")
          line(
            section,
            "p",
            "Exact resource address match",
            "reference-provenance",
          );
        if (
          !match.resource &&
          !match.identity &&
          !match.enrichment &&
          !match.network
        )
          details(section, match);
        details(section, match.network);
        details(section, match.resource);
        details(section, match.resource?.details);
        details(section, match.enrichment);
        details(section, match.identity);
        iamDetails(section, match);
        card.append(section);
      }
      if (matches.some((match) => match.source === "inventory")) {
        line(
          card,
          "p",
          "Inventory describes current configuration only; it is not proof of incident-time ownership or reachability.",
          "reference-warning",
        );
        const stamp =
          data.snapshot?.completed_at_utc ||
          data.snapshot?.started_at_utc ||
          data.snapshot?.collected_at ||
          data.snapshot?.collected ||
          data.snapshot?.collected_time;
        line(
          card,
          "p",
          `Snapshot collected: ${stamp || "not supplied"}`,
          "reference-provenance",
        );
      }
      if (data.kind === "identity" && data.iam_coverage?.started_at_utc) {
        line(
          card,
          "p",
          `IAM collected: ${data.iam_coverage.started_at_utc} to ${data.iam_coverage.completed_at_utc || "completion unknown"}`,
          "reference-provenance",
        );
        for (const error of data.iam_coverage.errors || [])
          line(
            card,
            "p",
            `IAM coverage gap: ${error.operation} · ${error.error}`,
            "reference-warning",
          );
      }
      if (data.matches.some((match) => match.source === "enrichment"))
        line(
          card,
          "p",
          "IP enrichment is an address lookup, not evidence of ownership.",
          "reference-provenance",
        );
      if (!data.history_included) {
        line(
          card,
          "p",
          "History not searched. Counts and first/last seen are available on request.",
          "reference-provenance",
        );
        const label =
          active.spec.kind === "machine"
            ? "Load command history"
            : "Load event history";
        const load = line(card, "button", label);
        load.type = "button";
        load.onclick = async () => {
          active.persistent = true;
          const token = sequence;
          load.disabled = true;
          load.textContent = "Loading history…";
          try {
            const history = await request("/api/reference", {
              ...active.spec,
              include_history: true,
            });
            if (token !== sequence || !active.element.isConnected) return;
            reveal(
              history,
              history.matches.length || history.network_matches?.length
                ? ""
                : "No matching history or loaded references.",
            );
            card.focus({ preventScroll: true });
          } catch (error) {
            if (token !== sequence) return;
            load.disabled = false;
            load.textContent = label;
            line(card, "p", error.message, "reference-warning");
            position();
          }
        };
      }
    }
    const host = active.element.closest("dialog") || document.body;
    if (card.parentElement !== host) host.append(card);
    card.hidden = false;
    if (!card.matches(":popover-open")) card.showPopover();
    active.element.setAttribute("aria-describedby", card.id);
    position();
  }

  async function open(element, spec, persistent) {
    clearTimeout(hoverTimer);
    clearTimeout(closeTimer);
    if (active?.element === element) {
      active.persistent ||= persistent;
      return;
    }
    if (active?.persistent && !persistent) return;
    close();
    const token = ++sequence;
    active = { element, spec, persistent };
    try {
      const data = await request("/api/reference", {
        ...spec,
        include_history: false,
      });
      if (sequence !== token || !element.isConnected) return;
      if (!Array.isArray(data.matches))
        throw new Error("Invalid reference response.");
      reveal(
        data,
        data.matches.length || data.network_matches?.length
          ? ""
          : "No known exact match in the loaded reference sources.",
      );
    } catch (error) {
      if (sequence !== token) return;
      if (active.persistent) reveal(null, error.message);
      else close();
    }
  }

  function scheduleClose() {
    clearTimeout(closeTimer);
    closeTimer = setTimeout(() => {
      if (!active?.persistent) close();
    }, 220);
  }

  function attach(element, { kind, value, region, account }) {
    if (
      !element ||
      attached.has(element) ||
      !["identity", "machine", "ip"].includes(kind) ||
      typeof value !== "string" ||
      !value.trim()
    )
      return;
    attached.add(element);
    const spec = { kind, value };
    if (region) spec.region = region;
    if (account) spec.account = account;
    element.classList.add("reference-trigger");
    if (!element.matches("button,a,input,[tabindex]")) element.tabIndex = 0;
    if (!element.matches("button,a,input"))
      element.setAttribute("role", "button");
    element.addEventListener("mouseenter", () => {
      clearTimeout(closeTimer);
      hoverTimer = setTimeout(() => open(element, spec, false), 300);
    });
    element.addEventListener("mouseleave", () => {
      clearTimeout(hoverTimer);
      scheduleClose();
    });
    element.addEventListener("focus", () => {
      if (!restoringFocus) open(element, spec, true);
    });
    element.addEventListener("click", (event) => {
      // Existing buttons/links keep their primary action; standalone value triggers open context.
      if (!element.matches("button,a")) {
        event.preventDefault();
        event.stopPropagation();
      }
      open(element, spec, true);
    });
    element.addEventListener("keydown", (event) => {
      if (
        (event.key === "Enter" || event.key === " ") &&
        !element.matches("button,a")
      ) {
        event.preventDefault();
        event.stopPropagation();
        open(element, spec, true);
      }
    });
  }
  card.addEventListener("mouseenter", () => clearTimeout(closeTimer));
  card.addEventListener("mouseleave", scheduleClose);
  card.addEventListener("focusin", () => {
    if (active) active.persistent = true;
  });
  document.addEventListener(
    "keydown",
    (event) => {
      if (event.key === "Escape" && active) {
        event.preventDefault();
        event.stopImmediatePropagation();
        close();
      }
    },
    true,
  );
  document.addEventListener(
    "pointerdown",
    (event) => {
      if (
        active &&
        !card.contains(event.target) &&
        !active.element.contains(event.target)
      )
        close();
    },
    true,
  );
  window.addEventListener("resize", position);
  document.addEventListener(
    "scroll",
    (event) => {
      if (!card.contains(event.target)) {
        // Focusing a horizontally clipped grid cell scrolls it into view. Keep its deliberate
        // lookup alive (including an in-flight reply), rather than immediately dismissing it.
        if (active?.persistent) position();
        else if (active) close();
      }
    },
    true,
  );
  window.kamotraceReference = { attach, close };
})();
