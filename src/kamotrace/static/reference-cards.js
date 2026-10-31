/* Exact-match, read-only context. Never inspect command output or raw evidence JSON. */
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
  card.setAttribute("aria-label", "Exact-match reference");
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
      for (const match of data.matches) {
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
        if (!match.resource && !match.identity && !match.enrichment)
          details(section, match);
        details(section, match.resource);
        details(section, match.resource?.details);
        details(section, match.enrichment);
        details(section, match.identity);
        card.append(section);
      }
      if (data.matches.some((match) => match.source === "inventory")) {
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
      if (data.matches.some((match) => match.source === "enrichment"))
        line(
          card,
          "p",
          "IP enrichment is an address lookup, not evidence of ownership.",
          "reference-provenance",
        );
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
      const response = await fetch("/api/reference", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(spec),
      });
      if (!response.ok)
        throw new Error("Reference lookup unavailable. Try again later.");
      const data = await response.json();
      if (sequence !== token || !element.isConnected) return;
      if (!Array.isArray(data.matches))
        throw new Error("Invalid reference response.");
      if (data.matches.length) reveal(data);
      else if (active.persistent)
        reveal(null, "No known exact match in the loaded reference sources.");
      else close();
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
