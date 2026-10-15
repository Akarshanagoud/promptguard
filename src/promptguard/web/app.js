/* PromptGuard console: views over the /v1/ui API. */
(function () {
  "use strict";
  const { h, api, fmt } = Kit;

  const ACTION = {
    allow: { kind: "good", label: "Allowed", color: "var(--good)" },
    flag: { kind: "warning", label: "Flagged", color: "var(--warning)" },
    redact: { kind: "serious", label: "Redacted", color: "var(--serious)" },
    block: { kind: "critical", label: "Blocked", color: "var(--critical)" },
  };
  const ACTION_ORDER = ["allow", "flag", "redact", "block"];
  const SEVERITY_KIND = { info: "", low: "info", medium: "warning", high: "serious", critical: "critical" };
  const CATEGORY = {
    prompt_injection: "Prompt injection",
    jailbreak: "Jailbreak",
    pii: "Personal data",
    secret: "Credentials",
    toxicity: "Toxicity",
    schema: "Output schema",
    input_limit: "Input limit",
  };
  const SAMPLE_GROUP = { benign: "Benign", injection: "Injection", jailbreak: "Jailbreak", pii: "Personal data", secret: "Credentials" };
  const FRAMEWORK = { owasp_llm: "OWASP LLM Top 10", nist_ai_rmf: "NIST AI RMF", eu_ai_act: "EU AI Act" };
  const CHANNEL = { user: "User message", retrieved: "Retrieved document", tool: "Tool output" };

  let metaCache = null;
  const meta = async () => metaCache || (metaCache = await api.get("/v1/ui/meta"));

  const actionBadge = (a) => Kit.badge((ACTION[a] || { label: a }).label, (ACTION[a] || {}).kind);
  const severityBadge = (s) => Kit.badge(fmt.title(s), SEVERITY_KIND[s] || "", { icon: s !== "info" });
  const categoryLabel = (c) => CATEGORY[c] || fmt.title(c);
  const ruleCode = (id) => h("code", { class: "nowrap" }, id);
  const ruleList = (ids) =>
    ids.length ? h("span", null, ids.map((id, i) => [i ? ", " : null, ruleCode(id)])) : h("span", { class: "muted" }, "none");

  // ------------------------------------------------------------------ overview
  async function overview(view) {
    const data = await api.get("/v1/ui/summary");
    const simulate = (label) => {
      const btn = h("button", { class: "btn btn-primary", type: "button" }, label);
      btn.addEventListener("click", () =>
        Kit.withButton(btn, async () => {
          btn.textContent = "Sending traffic…";
          const r = await api.post("/v1/ui/simulate", { count: 50 });
          const d = r.input_decisions;
          Kit.toast(r.simulated + " requests evaluated: " + (d.block || 0) + " blocked, " + (d.redact || 0) + " redacted");
          app.refresh();
        }),
      );
      return btn;
    };
    const refresh = h("button", { class: "btn", type: "button", onclick: () => app.refresh() }, "Refresh");
    view.append(
      Kit.pageHead(
        "Overview",
        "Every decision the guard made in this session, computed from its own hash-chained audit records.",
        [refresh, simulate("Simulate 50 requests")],
      ),
    );

    if (!data.requests) {
      view.append(
        Kit.card({
          body: h(
            "div",
            { class: "empty" },
            h("strong", null, "No traffic yet"),
            h("span", null, "Send a realistic mix of support questions, prompt injections, jailbreaks and personal data through the guard, or try your own prompt."),
            h("div", { class: "row", style: { justifyContent: "center", marginTop: "14px" } }, simulate("Simulate traffic"), h("a", { class: "btn", href: "#/playground" }, "Open playground")),
          ),
        }),
      );
      return;
    }

    const ia = data.input_actions;
    const oa = data.output_actions;
    const req = data.requests;
    view.append(
      h(
        "div",
        { class: "grid cols-5" },
        Kit.stat({ label: "Requests evaluated", value: fmt.int(req), note: fmt.int(data.responses) + " model responses checked" }),
        Kit.stat({ label: "Blocked before the model", value: fmt.int(ia.block || 0), note: fmt.pct((ia.block || 0) / req) + " of requests" }),
        Kit.stat({ label: "Redacted", value: fmt.int((ia.redact || 0) + (oa.redact || 0)), note: fmt.int(ia.redact || 0) + " prompts, " + fmt.int(oa.redact || 0) + " responses" }),
        Kit.stat({ label: "Flagged for review", value: fmt.int(ia.flag || 0), note: "allowed, with findings" }),
        Kit.stat({ label: "Guard latency p95", value: fmt.ms(data.latency_ms.p95), note: "p50 " + fmt.ms(data.latency_ms.p50) + " · p99 " + fmt.ms(data.latency_ms.p99) }),
      ),
    );

    const tl = data.timeline;
    const windows = tl.windows;
    const series = ACTION_ORDER.map((k) => ({ name: ACTION[k].label, color: ACTION[k].color, values: windows.map((w) => w[k]) }));
    const timelineCard = Kit.chartCard({
      title: "Decision mix over time",
      subtitle: "Input decisions in windows of " + tl.window + " requests, oldest to newest",
      legend: ACTION_ORDER.map((k) => ({ label: ACTION[k].label, color: ACTION[k].color })),
      chart: () =>
        Kit.columns({
          labels: windows.map((w) => w.last),
          series,
          height: 240,
          yFormat: fmt.compact,
          xFormat: (l) => "#" + l,
          tooltipTitle: (_, i) => "Requests " + windows[i].first + "–" + windows[i].last + " · " + fmt.time(windows[i].started),
          ariaLabel: "Stacked columns of input decisions per window of requests",
        }),
      table: () => ({
        columns: [{ key: "range", label: "Requests" }].concat(ACTION_ORDER.map((k) => ({ key: k, label: ACTION[k].label, align: "right" }))),
        rows: windows.map((w) => Object.assign({ range: w.first + "–" + w.last }, w)),
      }),
    });

    const cats = Object.entries(data.categories).map(([k, v]) => ({ label: categoryLabel(k), value: v }));
    const categoryCard = Kit.chartCard({
      title: "Findings by category",
      subtitle: "Across prompts and responses",
      chart: () => Kit.hbars(cats, { valueLabel: "Findings", format: fmt.int, emptyTitle: "No findings", emptyText: "Everything so far was clean." }),
      table: () => ({ columns: [{ key: "label", label: "Category" }, { key: "value", label: "Findings", align: "right" }], rows: cats }),
    });

    const rules = data.top_rules.map((r) => ({ label: r.rule_id, value: r.count, extra: [{ label: r.message, value: "" }] }));
    const rulesCard = Kit.chartCard({
      title: "Most frequent rules",
      subtitle: "Which detectors are doing the work",
      chart: () => Kit.hbars(rules, { valueLabel: "Hits", format: fmt.int, emptyTitle: "No rules fired yet" }),
      table: () => ({ columns: [{ key: "rule_id", label: "Rule" }, { key: "message", label: "Detects" }, { key: "count", label: "Hits", align: "right" }], rows: data.top_rules }),
    });

    const controlsCard = Kit.card({
      title: "Controls with evidence",
      subtitle: "Findings mapped to the compliance frameworks in the active policy",
      flush: true,
      body: Kit.table({
        columns: [
          { key: "framework", label: "Framework", render: (r) => FRAMEWORK[r.framework] || r.framework },
          { key: "control_id", label: "Control", render: (r) => h("code", null, r.control_id) },
          { key: "title", label: "Requirement", cls: "hide-sm" },
          { key: "count", label: "Evidence", align: "right" },
        ],
        rows: data.controls,
        emptyTitle: "No control evidence yet",
      }),
    });

    const recentCard = Kit.card({
      title: "Latest decisions",
      subtitle: "Newest first. Open the audit trail for the full chain.",
      actions: h("a", { class: "btn btn-sm", href: "#/audit" }, "Audit trail"),
      flush: true,
      body: recentTable(data.recent),
    });

    view.append(
      h("div", { class: "split-r mt" }, h("div", { class: "stack" }, timelineCard, controlsCard), h("div", { class: "stack" }, categoryCard, rulesCard)),
      h("div", { class: "mt" }, recentCard),
    );
  }

  function recentTable(rows) {
    return Kit.table({
      columns: [
        { key: "timestamp", label: "Time", render: (r) => h("span", { class: "num nowrap" }, fmt.time(r.timestamp)) },
        { key: "stage", label: "Stage", render: (r) => fmt.title(r.stage) },
        { key: "channel", label: "Channel", cls: "hide-sm", render: (r) => (r.channel ? CHANNEL[r.channel] || r.channel : "—") },
        { key: "action", label: "Decision", render: (r) => actionBadge(r.action) },
        { key: "risk_score", label: "Risk", align: "right", format: (v) => fmt.num(v, 2) },
        { key: "rules", label: "Rules", sortable: false, cls: "hide-sm", render: (r) => ruleList(r.rules) },
      ],
      rows,
      emptyTitle: "No decisions yet",
    });
  }

  // ------------------------------------------------------------------ playground
  // Evidence for card numbers and secrets is masked ("****1111"), so a span is
  // trusted when every unmasked character agrees with the text it points at.
  function agrees(slice, evidence) {
    if (!evidence) return true;
    if (slice === evidence) return true;
    if (slice.length !== evidence.length) return false;
    for (let i = 0; i < evidence.length; i++) {
      if (evidence[i] !== "*" && evidence[i] !== slice[i]) return false;
    }
    return true;
  }

  function locateSpans(text, findings) {
    const spans = [];
    for (const f of findings) {
      let start = null;
      let end = null;
      if (f.span && text.slice(f.span[0], f.span[1]) && agrees(text.slice(f.span[0], f.span[1]), f.evidence)) {
        [start, end] = f.span;
      } else if (f.evidence) {
        const at = text.indexOf(f.evidence);
        if (at >= 0) {
          start = at;
          end = at + f.evidence.length;
        }
      }
      if (start !== null) spans.push({ start, end, cls: f.severity === "critical" || f.severity === "high" ? "m-critical" : "", title: f.rule_id + ": " + f.message });
    }
    return spans;
  }

  function findingsTable(findings) {
    return Kit.table({
      columns: [
        { key: "rule_id", label: "Rule", render: (f) => ruleCode(f.rule_id) },
        { key: "category", label: "Category", render: (f) => categoryLabel(f.category) },
        { key: "severity", label: "Severity", render: (f) => severityBadge(f.severity), sortValue: (f) => ["info", "low", "medium", "high", "critical"].indexOf(f.severity) },
        { key: "message", label: "What it detected", cls: "hide-sm" },
        { key: "evidence", label: "Evidence", sortable: false, cls: "hide-sm", render: (f) => (f.evidence ? h("code", null, f.evidence) : "—") },
      ],
      rows: findings,
      emptyTitle: "No findings",
      emptyText: "Nothing in this text matched a rule.",
    });
  }

  const DECISION_TEXT = {
    input: {
      allow: "Allowed: clean, sent to the model unchanged",
      flag: "Flagged: sent to the model and marked for review",
      redact: "Redacted: sensitive values removed before the model saw them",
      block: "Blocked: the model was never called",
    },
    output: {
      allow: "Allowed: response served unchanged",
      flag: "Flagged: response served and marked for review",
      redact: "Redacted: sensitive values removed before the user saw them",
      block: "Blocked: response replaced with a refusal",
    },
  };

  function decisionCard(stage, result, extra) {
    const a = ACTION[result.action] || { kind: "" };
    const body = h(
      "div",
      { class: "stack" },
      Kit.banner({
        kind: a.kind,
        title: DECISION_TEXT[stage][result.action] || result.action,
        text:
          "Risk " + fmt.num(result.risk_score, 2) + " after remediation (" + fmt.num(result.detected_risk, 2) + " detected) · highest severity " + result.max_severity + " · " + fmt.ms(result.elapsed_ms),
        extra: h("div", { style: { marginTop: "8px", maxWidth: "320px" } }, Kit.meter(result.risk_score, a.kind, "Residual risk")),
      }),
      h("div", null, h("div", { class: "small muted", style: { marginBottom: "6px" } }, stage === "input" ? "Prompt as received" : "Model response as generated"), h("div", { class: "doc" }, Kit.highlight(result.original, locateSpans(result.original, result.findings)))),
      findingsTable(result.findings),
      result.modified && result.action !== "block"
        ? h("div", null, h("div", { class: "small muted", style: { marginBottom: "6px" } }, stage === "input" ? "Sent to the model" : "Served to the user"), h("div", { class: "codebox" }, result.text))
        : null,
      extra || null,
    );
    return Kit.card({ title: stage === "input" ? "Input guard" : "Output guard", subtitle: stage === "input" ? "Runs before the model is called" : "Runs on the model's reply before the user sees it", body });
  }

  async function playground(view, params) {
    const m = await meta();
    const prompts = m.samples.prompts;
    const replies = m.samples.responses;
    const state = { preset: m.presets.includes(m.policy) ? m.policy : "default" };

    const promptBox = h("textarea", { class: "textarea", rows: "5", placeholder: "Type a prompt, or pick a sample above", "aria-label": "Prompt" });
    promptBox.value = params.prompt || prompts[0].text;
    const channel = Kit.select(Object.entries(CHANNEL).map(([value, label]) => ({ value, label })), "user");
    const responseBox = h("textarea", { class: "textarea", rows: "3", placeholder: "Optional. Leave empty to use a stand-in reply.", "aria-label": "Model response" });

    const groups = {};
    prompts.forEach((p) => (groups[p.category] = groups[p.category] || []).push(p));
    const chipsFor = Object.entries(groups).map(([cat, items]) =>
      h(
        "div",
        { class: "chip-group" },
        h("b", null, SAMPLE_GROUP[cat] || cat),
        h(
          "div",
          { class: "chips" },
          items.map((p) =>
            h(
              "button",
              {
                class: "chip",
                type: "button",
                title: p.text,
                onclick: () => {
                  promptBox.value = p.text;
                  channel.value = p.channel;
                },
              },
              p.label,
            ),
          ),
        ),
      ),
    );
    const replyChips = h(
      "div",
      { class: "chips" },
      replies.map((r) => h("button", { class: "chip", type: "button", title: r.text, onclick: () => (responseBox.value = r.text) }, r.label)),
    );

    const results = h("div", { class: "stack" }, Kit.card({ body: Kit.empty("Run a prompt to see each stage of the decision", "The input guard runs first. If it allows the request, the model's reply goes through the output guard.") }));
    const run = h("button", { class: "btn btn-primary", type: "submit" }, "Run through the guard");

    const form = h(
      "form",
      { class: "stack" },
      h("div", { class: "stack", style: { gap: "8px" } }, chipsFor),
      Kit.field("Prompt", promptBox),
      h("div", { class: "grid cols-2" }, Kit.field("Arrives as", channel), Kit.field("Policy preset", Kit.seg(m.presets.map((p) => ({ value: p, label: fmt.title(p) })), state.preset, (v) => (state.preset = v)))),
      h("details", null, h("summary", { class: "small", style: { cursor: "pointer", color: "var(--ink-2)" } }, "Model response (optional)"), h("div", { class: "stack", style: { marginTop: "10px", gap: "8px" } }, replyChips, responseBox)),
      h("div", { class: "row-between" }, h("span", { class: "small muted" }, "No model is connected. Decisions are real; the reply is yours or a stand-in."), run),
    );
    form.addEventListener("submit", (e) => {
      e.preventDefault();
      if (!promptBox.value.trim()) {
        Kit.toast("Enter a prompt first", "error");
        return;
      }
      Kit.withButton(run, async () => {
        run.textContent = "Evaluating…";
        const r = await Kit.busy(results, () =>
          api.post("/v1/ui/turn", { prompt: promptBox.value, response: responseBox.value || null, channel: channel.value, preset: state.preset }),
        );
        renderTurn(results, r);
      });
    });

    view.append(
      Kit.pageHead("Playground", "Send one request through the full guarded turn: input guard, model, output guard. Every run is written to the audit trail."),
      h("div", { class: "split" }, Kit.card({ title: "Request", body: form }), results),
    );
  }

  function stageBox(name, content, skipped) {
    return h("div", { class: "stage" + (skipped ? " skipped" : "") }, h("div", { class: "stage-name" }, name), content);
  }

  function renderTurn(host, r) {
    Kit.clear(host);
    const outputSkipped = !r.output;
    host.append(
      Kit.card({
        title: "Decision path",
        subtitle: "Request " + fmt.short(r.request_id) + " · policy " + r.preset,
        body: h(
          "div",
          { class: "stack" },
          h(
            "div",
            { class: "pipeline" },
            stageBox("1. Input guard", actionBadge(r.input.action)),
            stageBox("2. Model", r.model_called ? Kit.badge(r.stand_in ? "Called (stand-in reply)" : "Called", "info", { icon: false }) : Kit.badge("Not called", "", { icon: false }), !r.model_called),
            stageBox("3. Output guard", outputSkipped ? Kit.badge("Skipped", "", { icon: false }) : actionBadge(r.output.action), outputSkipped),
            stageBox("4. Served to user", r.blocked_at ? Kit.badge("Refusal", "critical") : Kit.badge("Response", "good")),
          ),
          h("div", null, h("div", { class: "small muted", style: { marginBottom: "6px" } }, "What the user receives"), h("div", { class: "codebox" }, r.served)),
        ),
      }),
      decisionCard("input", r.input),
    );
    if (r.output) host.append(decisionCard("output", r.output));
  }

  // ------------------------------------------------------------------ audit
  async function audit(view) {
    const data = await api.get("/v1/ui/audit?limit=300");
    const exportBtn = h("button", { class: "btn", type: "button" }, "Export JSONL");
    exportBtn.addEventListener("click", () =>
      Kit.withButton(exportBtn, async () => {
        const res = await fetch("/v1/ui/audit/export");
        Kit.download("promptguard-audit.jsonl", await res.text(), "application/x-ndjson");
      }),
    );
    view.append(
      Kit.pageHead("Audit trail", "Append-only and hash-chained: each record stores the SHA-256 of the one before it, so an edited or deleted line breaks verification.", [
        h("button", { class: "btn", type: "button", onclick: () => app.refresh() }, "Re-verify"),
        exportBtn,
      ]),
    );
    view.append(
      data.intact
        ? Kit.banner({
            kind: "good",
            title: "Chain intact: " + fmt.int(data.total) + " records verified",
            text: "Head " + fmt.short(data.head, 16) + "… · " + (data.persisted_to ? "persisted to " + data.persisted_to : "held in memory for this session (pass --audit-log to persist)"),
          })
        : Kit.banner({ kind: "critical", title: "Chain broken", text: "First bad record: " + data.broken_at }),
    );

    const detail = h("div", null, Kit.card({ body: Kit.empty("Select a record", "Its hashes and findings appear here.") }));
    const tableCard = Kit.card({
      title: "Records",
      subtitle: "Newest first. Payloads are not stored, only their SHA-256.",
      flush: true,
      body: Kit.table({
        columns: [
          { key: "timestamp", label: "Time", render: (r) => h("span", { class: "num nowrap" }, fmt.time(r.timestamp)) },
          { key: "stage", label: "Stage", render: (r) => fmt.title(r.stage) },
          { key: "action", label: "Decision", render: (r) => actionBadge(r.action) },
          { key: "risk_score", label: "Risk", align: "right", format: (v) => fmt.num(v, 2) },
          { key: "rules", label: "Rules", sortable: false, cls: "hide-sm", render: (r) => ruleList(r.rules) },
          {
            key: "record_hash",
            label: "Chain",
            sortable: false,
            cls: "hide-sm",
            render: (r) => h("span", { class: "chain hash" }, fmt.short(r.prev_hash, 7), h("span", { class: "arrow" }, "→"), fmt.short(r.record_hash, 7)),
          },
        ],
        rows: data.records,
        rowKey: (r) => r.event_id,
        maxHeight: 560,
        onRowClick: (r) => {
          Kit.clear(detail);
          detail.append(
            Kit.card({
              title: "Record " + fmt.short(r.event_id),
              subtitle: new Date(r.timestamp).toLocaleString(),
              body: h(
                "div",
                { class: "stack" },
                Kit.kv([
                  ["Decision", actionBadge(r.action)],
                  ["Stage", fmt.title(r.stage) + (r.channel ? " · " + (CHANNEL[r.channel] || r.channel) : "")],
                  ["Request", h("code", null, r.request_id)],
                  ["Risk", fmt.num(r.risk_score, 4) + " · highest severity " + r.max_severity],
                  ["Guard time", fmt.ms(r.elapsed_ms)],
                  ["Payload", fmt.int(r.input_chars) + " characters" + (r.modified ? ", rewritten" : "")],
                  ["Categories", r.categories.length ? r.categories.map(categoryLabel).join(", ") : "none"],
                  ["Rules", ruleList(r.rules)],
                ]),
                h("div", null, h("div", { class: "small muted" }, "Payload SHA-256"), h("div", { class: "hash", style: { overflowWrap: "anywhere" } }, r.payload_sha256)),
                h("div", null, h("div", { class: "small muted" }, "Previous record hash"), h("div", { class: "hash", style: { overflowWrap: "anywhere" } }, r.prev_hash)),
                h("div", null, h("div", { class: "small muted" }, "This record hash"), h("div", { class: "hash", style: { overflowWrap: "anywhere" } }, r.record_hash)),
              ),
            }),
          );
        },
        emptyTitle: "No records yet",
        emptyText: "Run the playground or simulate traffic from the overview.",
      }),
    });
    view.append(h("div", { class: "split-r mt" }, tableCard, detail));
  }

  // ------------------------------------------------------------------ rules
  async function rules(view) {
    const data = await api.get("/v1/ui/rules");
    const presetRows = data.presets.map((p) => Object.assign({ active: p.name === data.active.name }, p));
    const presetCard = Kit.card({
      title: "Policy presets",
      subtitle: "The same detectors, different enforcement. Switch presets in the playground to compare decisions.",
      flush: true,
      body: Kit.table({
        columns: [
          { key: "name", label: "Preset", render: (p) => h("span", { class: "row" }, h("b", null, fmt.title(p.name)), p.active ? Kit.badge("Active", "info", { icon: false }) : null) },
          { key: "input_block_threshold", label: "Block at risk", align: "right", format: (v) => (v > 1 ? "never" : fmt.num(v, 2)) },
          { key: "input_flag_threshold", label: "Flag at risk", align: "right", format: (v) => fmt.num(v, 2) },
          { key: "input_block_on_severity", label: "Always block", render: (p) => severityBadge(p.input_block_on_severity) },
          { key: "redact_pii_in_output", label: "Redact PII in output", cls: "hide-sm", render: (p) => (p.redact_pii_in_output ? "Yes" : "No") },
          { key: "fail_open", label: "On error", cls: "hide-sm", render: (p) => (p.fail_open ? "Fail open" : "Fail closed") },
        ],
        rows: presetRows,
      }),
    });

    const search = h("input", { class: "input", type: "search", placeholder: "Filter by rule, category or detail", "aria-label": "Filter rules" });
    let category = "all";
    const counts = {};
    data.rules.forEach((r) => (counts[r.category] = (counts[r.category] || 0) + 1));
    const tbl = Kit.table({
      columns: [
        { key: "rule_id", label: "Rule", render: (r) => ruleCode(r.rule_id) },
        { key: "category", label: "Category", render: (r) => categoryLabel(r.category) },
        { key: "severity", label: "Severity", render: (r) => severityBadge(r.severity), sortValue: (r) => ["info", "low", "medium", "high", "critical"].indexOf(r.severity) },
        { key: "detail", label: "Detects" },
      ],
      rows: data.rules,
      sort: { key: "rule_id", dir: "asc" },
      maxHeight: 600,
    });
    const apply = () => {
      const q = search.value.trim().toLowerCase();
      tbl.update(
        data.rules.filter((r) => (category === "all" || r.category === category) && (!q || (r.rule_id + " " + r.category + " " + r.detail).toLowerCase().includes(q))),
      );
    };
    search.addEventListener("input", apply);
    const chips = h(
      "div",
      { class: "chips" },
      [["all", "All (" + data.rules.length + ")"]].concat(Object.entries(counts).map(([c, n]) => [c, categoryLabel(c) + " (" + n + ")"])).map(([value, label]) => {
        const b = h("button", { class: "chip", type: "button", "aria-pressed": String(value === "all") }, label);
        b.addEventListener("click", () => {
          category = value;
          chips.querySelectorAll(".chip").forEach((x) => x.setAttribute("aria-pressed", "false"));
          b.setAttribute("aria-pressed", "true");
          apply();
        });
        return b;
      }),
    );
    view.append(
      Kit.pageHead("Rules and policy", data.rules.length + " detection rules across injection, jailbreak, credential and personal-data detectors. Output adds toxicity and schema checks."),
      presetCard,
      Kit.card({ cls: "mt", title: "Detection rules", body: h("div", { class: "stack" }, h("div", { class: "row-between" }, chips, h("div", { style: { width: "280px", maxWidth: "100%" } }, search)), tbl) }),
    );
  }

  const app = Kit.createApp({
    title: "PromptGuard Console",
    health: "/health",
    healthLabel: (info) => "policy " + info.policy + " · v" + info.version,
    routes: [
      { path: "overview", label: "Overview", render: overview },
      { path: "playground", label: "Playground", render: playground },
      { path: "audit", label: "Audit trail", render: audit },
      { path: "rules", label: "Rules", render: rules },
    ],
  });
})();
