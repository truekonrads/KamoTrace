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

  // These are configuration review leads, never an IAM authorization evaluator.
  function iamReview(match, coverage = {}) {
    const iam = match.iam;
    const list = (value) => (Array.isArray(value) ? value : []);
    const values = (value) =>
      value == null ? [] : Array.isArray(value) ? value : [value];
    const signals = [];
    const add = (label, detail, level = "review") =>
      signals.push({ label, detail, level });
    const collected = Date.parse(coverage.completed_at_utc);
    const days = (value) => {
      const elapsed = collected - Date.parse(value);
      return Number.isFinite(elapsed) && elapsed >= 0
        ? Math.floor(elapsed / 86400000)
        : null;
    };
    if (iam.UserName) {
      const activity = iam.activity;
      if (
        !activity ||
        activity.console_status !== "collected" ||
        activity.access_keys_status !== "collected"
      )
        add(
          "Credential coverage gap",
          "Console activity or access-key listing was not collected or is incomplete. Recorded keys may be only a partial list.",
          "unknown",
        );
      for (const key of list(activity?.access_keys)) {
        if (key.last_used_status !== "collected")
          add(
            "Key usage unknown",
            `${key.AccessKeyId}: last-use lookup failed or was incomplete.`,
            "unknown",
          );
        if (key.Status !== "Active") continue;
        const age = days(key.CreateDate),
          idle = days(key.last_used?.LastUsedDate);
        if (age !== null && age >= 90)
          add(
            "Active key ≥90 days old",
            `${key.AccessKeyId}: created ${key.CreateDate}; ${age} days old at collection. Review whether this long-lived credential is still required.`,
          );
        if (key.last_used_status === "collected" && idle !== null && idle >= 90)
          add(
            "Active key last used ≥90 days ago",
            `${key.AccessKeyId}: AWS last reported use ${key.last_used.LastUsedDate}; ${idle} days before collection. Review continued need.`,
          );
        else if (
          key.last_used_status === "collected" &&
          !key.last_used?.LastUsedDate
        )
          add(
            "Active key usage unreported",
            `${key.AccessKeyId}: AWS supplied no last-use timestamp. This does not establish that the key was never used.`,
            "unknown",
          );
      }
      if (
        activity?.mfa_status !== "collected" ||
        !["collected", "not_configured"].includes(
          activity?.login_profile_status,
        )
      )
        add(
          "MFA / console credential posture unknown",
          "MFA enrollment or console-password configuration was not collected completely. A sign-in timestamp is not an MFA or password-status check.",
          "unknown",
        );
      else if (
        activity.login_profile_status === "collected" &&
        !list(activity.mfa_devices).length
      )
        add(
          "Console password with no enrolled MFA",
          "At IAM collection, a login profile existed and no MFA devices were enrolled. Review authentication controls; this snapshot does not establish historical MFA use or enforcement.",
        );
    }
    if (iam.RoleName) {
      const idle = days(iam.RoleLastUsed?.LastUsedDate);
      if (idle !== null && idle >= 90)
        add(
          "Role last used ≥90 days ago",
          `AWS last reported use ${iam.RoleLastUsed.LastUsedDate}; ${idle} days before collection. Review continued need; AWS reporting is not complete historical activity.`,
        );
      else if (!iam.RoleLastUsed?.LastUsedDate)
        add(
          "Role usage unreported",
          "AWS supplied no role last-use timestamp. This does not establish that the role was never used.",
          "unknown",
        );
      if (!iam.AssumeRolePolicyDocument)
        add(
          "Trust policy unavailable",
          "The role trust policy was not collected.",
          "unknown",
        );
      for (const [index, statement] of values(
        iam.AssumeRolePolicyDocument?.Statement,
      ).entries()) {
        if (statement.Effect !== "Allow") continue;
        const source = `Trust statement ${statement.Sid || index + 1}`;
        const condition =
          statement.Condition && Object.keys(statement.Condition).length
            ? " Conditions are present; inspect their restrictions."
            : " No conditions are recorded on this statement.";
        const principals =
          statement.Principal === "*"
            ? ["*"]
            : Object.values(statement.Principal || {}).flatMap(values);
        if (principals.includes("*"))
          add(
            "Wildcard trust principal",
            `${source} allows a wildcard principal.${condition} Other statements and controls are not evaluated.`,
          );
        const account = iam.Arn?.split(":")[4];
        const external = values(statement.Principal?.AWS).filter(
          (principal) => {
            const owner =
              /^arn:[^:]+:iam::([^:]+):/.exec(principal)?.[1] ||
              (/^\d+$/.test(principal) ? principal : null);
            return owner && account && owner !== account;
          },
        );
        if (external.length)
          add(
            "Cross-account trust",
            `${source} names ${external.join(", ")}.${condition} This is configured trust, not proof of assumable access.`,
          );
        if (statement.NotPrincipal)
          add(
            "Trust uses NotPrincipal",
            `${source} uses inverse principal matching. Inspect the document and conditions; trust is not evaluated.`,
          );
      }
    }
    const documents = [];
    function managed(policy, source) {
      const version = list(policy?.PolicyVersionList).find(
        (v) =>
          v.VersionId === policy.DefaultVersionId ||
          (policy.DefaultVersionId == null && v.IsDefaultVersion),
      );
      if (version?.Document) documents.push([source, version.Document]);
      else
        add(
          "Policy document unavailable",
          `${source}: ${policy?.aws_managed ? "AWS-managed metadata only" : "default version not collected"}. Permissions are unknown.`,
          "unknown",
        );
    }
    for (const owner of [iam, ...list(match.iam_groups)]) {
      const ownerName = owner.UserName || owner.RoleName || owner.GroupName;
      for (const policy of [
        ...list(owner.UserPolicyList),
        ...list(owner.RolePolicyList),
        ...list(owner.GroupPolicyList),
      ]) {
        const source = `${ownerName} / ${policy.PolicyName}`;
        if (policy.PolicyDocument)
          documents.push([source, policy.PolicyDocument]);
        else
          add(
            "Policy document unavailable",
            `${source}: inline document not collected.`,
            "unknown",
          );
      }
      for (const ref of list(owner.AttachedManagedPolicies))
        managed(
          list(match.iam_policies).find((p) => p.Arn === ref.PolicyArn),
          `${ownerName} / ${ref.PolicyName || ref.PolicyArn}`,
        );
    }
    if (iam.PolicyName) managed(iam, iam.PolicyName);
    for (const name of list(iam.GroupList))
      if (!list(match.iam_groups).some((g) => g.GroupName === name))
        add(
          "Group policy coverage gap",
          `${name}: group configuration not collected. Inherited permissions are unknown.`,
          "unknown",
        );
    for (const [source, document] of documents) {
      for (const [index, statement] of values(document.Statement).entries()) {
        if (statement.Effect !== "Allow") continue;
        const actions = values(statement.Action).filter(
          (action) => action === "*" || /^[^:]+:\*$/.test(action),
        );
        const allResources = values(statement.Resource).includes("*");
        const condition =
          statement.Condition && Object.keys(statement.Condition).length
            ? " Conditions are present."
            : "";
        const evidence = `${source}, statement ${statement.Sid || index + 1}`;
        if (actions.length)
          add(
            "Broad action allow",
            `${evidence}: Action ${actions.join(", ")}; Resource ${values(statement.Resource).join(", ") || "not supplied"}.${condition} Denies, boundaries and other controls may restrict this statement.`,
          );
        else if (allResources)
          add(
            "All-resource allow",
            `${evidence}: Action ${values(statement.Action).join(", ") || "not supplied"}; Resource *.${condition} Some actions require this scope; review whether it is necessary.`,
          );
        if (statement.NotAction || statement.NotResource)
          add(
            "Inverse permission scope",
            `${evidence} uses NotAction or NotResource. Inspect the document; permissions are not evaluated.`,
          );
      }
    }
    if (list(coverage.errors).length)
      add(
        "IAM collection errors",
        `${coverage.errors.length} failed or incomplete IAM reads were recorded. Review coverage before drawing conclusions.`,
        "unknown",
      );
    return signals;
  }

  function renderIamReview(parent, signals, coverage = {}) {
    const section = line(parent, "section", "", "iam-review");
    line(section, "h3", "Review signals");
    line(
      section,
      "p",
      "Configuration leads, not confirmed vulnerabilities or effective permissions. Key age and inactivity use a 90-day review threshold at snapshot collection, not today.",
      "reference-provenance",
    );
    if (coverage.completed_at_utc)
      line(
        section,
        "p",
        `IAM collected: ${coverage.completed_at_utc}`,
        "reference-provenance",
      );
    else
      line(
        section,
        "p",
        "Collection time unavailable; age-based checks could not be made.",
        "reference-provenance",
      );
    for (const signal of signals.filter((s) => s.level === "review")) {
      const entry = line(
        section,
        "details",
        "",
        "iam-signal iam-signal-review",
      );
      line(entry, "summary", signal.label);
      line(entry, "p", signal.detail);
    }
    const unknown = signals.filter((s) => s.level === "unknown");
    if (unknown.length) {
      const coverageDetails = line(
        section,
        "details",
        "",
        "iam-signal iam-signal-unknown",
      );
      line(
        coverageDetails,
        "summary",
        `Coverage / unknowns (${unknown.length})`,
      );
      for (const signal of unknown) {
        line(coverageDetails, "strong", signal.label);
        line(coverageDetails, "p", signal.detail);
      }
    }
    if (!signals.length)
      line(
        section,
        "p",
        "No signals from these limited checks. This is not a safety assessment; MFA enforcement, effective permissions and historical changes are not evaluated.",
      );
  }

  function mfaEvidence(parent, data) {
    parent.replaceChildren();
    line(parent, "h3", "Observed CloudTrail MFA");
    const coverage = data.history_coverage;
    line(
      parent,
      "p",
      `Imported event range (UTC): ${coverage?.first_event || "no dated events"} to ${coverage?.last_event || "no dated events"}. ${coverage?.scope || "Coverage unavailable"}. Account: ${coverage?.account || "all"}; region: ${coverage?.region || "all"}.`,
      "reference-provenance",
    );
    line(
      parent,
      "p",
      data.history_association ||
        "Exact historical identity lookup; current configuration does not establish incident-time ownership.",
      "reference-provenance",
    );
    line(
      parent,
      "p",
      "Observed events only. Missing logs or MFA fields are unknown, not proof of no MFA. Session MFA flags describe AWS credential context, not a new MFA challenge per API call; upstream IdP / Identity Center MFA may not be represented.",
      "reference-warning",
    );
    const matches = data.matches.filter(
      (m) => m.source === "cloudtrail" && m.mfa,
    );
    if (!matches.length)
      line(
        parent,
        "p",
        "No matching CloudTrail events for this lookup. This does not establish that the identity was unused or MFA was absent.",
      );
    for (const match of matches) {
      const group = line(parent, "details", "", "reference-mfa-observation");
      line(
        group,
        "summary",
        `${match.identity.event_count} events${match.mfa.console_success_without_mfa ? `; ${match.mfa.console_success_without_mfa} successful sign-ins reported MFAUsed=No` : ""} · ${match.region || "region unknown"} · ${match.identity.arn}`,
      );
      line(
        group,
        "p",
        `Principal ID: ${match.identity.principal_id || "not reported"}. Observed: ${match.identity.first_seen} to ${match.identity.last_seen} (UTC).`,
        "reference-provenance",
      );
      const counts = document.createElement("dl");
      for (const [key, label] of [
        ["console_success_with_mfa", "Successful sign-ins: MFAUsed=Yes"],
        ["console_success_without_mfa", "Successful sign-ins: MFAUsed=No"],
        ["console_success_mfa_unknown", "Successful sign-ins: MFA unknown"],
        [
          "console_failed_or_result_unknown",
          "Failed / unknown-result sign-ins",
        ],
        ["session_mfa_authenticated", "Other events: session MFA=true"],
        ["session_mfa_not_authenticated", "Other events: session MFA=false"],
        ["session_mfa_unknown", "Other events: session MFA unknown"],
      ]) {
        line(counts, "dt", label);
        line(counts, "dd", match.mfa[key]);
      }
      group.append(counts);
      if (match.mfa.console_success_without_mfa)
        line(
          group,
          "p",
          "Review lead: successful console sign-ins explicitly reported MFAUsed=No in the imported events. Current MFA enrollment does not change that historical observation.",
          "reference-warning",
        );
      policyDetails(
        group,
        "Supporting event hashes (one example per category)",
        match.mfa.samples,
      );
    }
  }

  function iamHistory(parent, spec, history) {
    const section = line(parent, "section", "", "reference-mfa-history");
    if (history?.history_included) return mfaEvidence(section, history);
    line(section, "h3", "Observed CloudTrail MFA");
    line(
      section,
      "p",
      "History not searched. Compare current IAM posture with MFA evidence in the imported event range; gaps remain unknown.",
      "reference-provenance",
    );
    const load = line(section, "button", "Load CloudTrail MFA evidence");
    load.type = "button";
    load.onclick = async () => {
      load.disabled = true;
      load.textContent = "Loading CloudTrail MFA evidence…";
      try {
        const result = await request("/api/reference", {
          ...spec,
          include_history: true,
        });
        if (!section.isConnected) return;
        mfaEvidence(section, result);
        if (card.contains(section)) position();
      } catch (error) {
        if (!section.isConnected) return;
        load.disabled = false;
        load.textContent = "Retry CloudTrail MFA evidence";
        line(section, "p", error.message, "reference-warning");
      }
    };
  }

  function iamDetails(parent, match, coverage = {}, context = {}) {
    const iam = match.iam;
    if (!iam || typeof iam !== "object") return;
    const list = (value) => (Array.isArray(value) ? value : []);
    parent = line(parent, "div", "", "reference-iam");
    renderIamReview(parent, iamReview(match, coverage), coverage);
    line(parent, "h3", "IAM configuration");
    details(parent, {
      name: iam.UserName || iam.RoleName || iam.GroupName,
      arn: iam.Arn,
      principal_id: iam.UserId || iam.RoleId || iam.GroupId,
    });
    const policyNames = (identity) =>
      [
        ...list(identity.UserPolicyList),
        ...list(identity.RolePolicyList),
        ...list(identity.GroupPolicyList),
        ...list(identity.AttachedManagedPolicies),
      ]
        .map((policy) => policy.PolicyName || policy.PolicyArn)
        .join(", ") || "None recorded";
    const activity = iam.activity;
    line(parent, "h3", "Identity summary");
    const summary = document.createElement("dl");
    summary.className = "reference-iam-summary";
    for (const [label, value] of [
      [
        "Identity type",
        iam.RoleName ? "IAM role" : iam.UserName ? "IAM user" : "IAM group",
      ],
      ["Role", iam.RoleName],
      [
        "Group memberships",
        iam.UserName
          ? list(iam.GroupList).join(", ") || "None recorded"
          : undefined,
      ],
      ["Direct policies", policyNames(iam)],
      [
        "Group policies",
        iam.UserName
          ? list(match.iam_groups)
              .map((group) => `${group.GroupName}: ${policyNames(group)}`)
              .join("; ") ||
            (list(iam.GroupList).length
              ? "Group configuration not collected"
              : "None recorded")
          : undefined,
      ],
      ["Created", iam.CreateDate],
      [
        "MFA enrollment",
        iam.UserName
          ? activity?.mfa_status === "collected"
            ? `${list(activity.mfa_devices).length} enrolled devices at collection`
            : "Unknown / not collected completely"
          : undefined,
      ],
      [
        "Console password",
        iam.UserName
          ? activity?.login_profile_status === "collected"
            ? "Login profile present at collection"
            : activity?.login_profile_status === "not_configured"
              ? "No login profile at collection"
              : "Unknown / not collected"
          : undefined,
      ],
      [
        "Password reset required",
        activity?.login_profile?.PasswordResetRequired,
      ],
      [
        "Role last used",
        iam.RoleName
          ? iam.RoleLastUsed?.LastUsedDate ||
            "Not reported by AWS; not proof of never used"
          : undefined,
      ],
      ["Last-used region", iam.RoleLastUsed?.Region],
      [
        "Console sign-in",
        iam.UserName
          ? !activity
            ? "Not collected"
            : activity.console_status !== "collected"
              ? "Unknown (collection failed or incomplete)"
              : activity.password_last_used ||
                "No sign-in timestamp reported by AWS"
          : undefined,
      ],
      [
        "Access keys",
        iam.UserName
          ? !activity
            ? "Not collected"
            : `${list(activity.access_keys).length} recorded${activity.access_keys_status === "collected" ? "" : "; listing incomplete or failed"}`
          : undefined,
      ],
      ["Maximum session (seconds)", iam.MaxSessionDuration],
    ]) {
      if (value == null) continue;
      line(summary, "dt", label);
      line(
        summary,
        "dd",
        typeof value === "object" ? JSON.stringify(value) : value,
      );
    }
    parent.append(summary);
    if (iam.UserName || iam.RoleName)
      iamHistory(
        parent,
        context.spec || {
          kind: "identity",
          value: iam.Arn,
          account: iam.Arn.split(":")[4],
        },
        context.history,
      );
    if (iam.UserName && activity?.mfa_devices?.length)
      policyDetails(
        parent,
        "Enrolled MFA devices at collection",
        activity.mfa_devices,
      );
    if (iam.UserName)
      line(
        parent,
        "p",
        "IAM users do not have role memberships. Assumable roles are not evaluated by this snapshot.",
        "reference-provenance",
      );
    if (activity) {
      line(parent, "h3", "Access-key activity");
      for (const key of list(activity.access_keys)) {
        const section = document.createElement("details");
        section.className = "reference-access-key";
        line(section, "summary", `${key.AccessKeyId} · ${key.Status}`);
        const facts = document.createElement("dl");
        for (const [label, value] of [
          ["Key ID", key.AccessKeyId],
          ["Status", key.Status],
          ["Created", key.CreateDate],
          [
            "Last used",
            key.last_used_status === "collected"
              ? key.last_used?.LastUsedDate ||
                "No last-use timestamp reported by AWS"
              : "Unknown (lookup failed or incomplete)",
          ],
          ["Last service", key.last_used?.ServiceName],
          ["Last region", key.last_used?.Region],
        ]) {
          if (value == null) continue;
          line(facts, "dt", label);
          line(facts, "dd", value);
        }
        section.append(facts);
        parent.append(section);
      }
      line(
        parent,
        "p",
        "AWS-reported credential activity, not CloudTrail history. Missing timestamps do not prove never used or that a console password is disabled. Secret access keys are not collected.",
        "reference-provenance",
      );
    }
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
        iamDetails(section, match, data.iam_coverage, {
          spec: active.spec,
          history: data,
        });
        if (
          data.kind === "identity" &&
          match.mfa &&
          !data.matches.some((m) => m.iam)
        )
          mfaEvidence(line(section, "section", "", "reference-mfa-history"), {
            ...data,
            matches: [match],
          });
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
  window.kamotraceReference = {
    attach,
    close,
    iamDetails,
    iamReview,
    renderIamReview,
  };
})();
