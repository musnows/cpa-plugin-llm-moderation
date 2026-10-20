"use strict";

const base = "/v0/management/plugins/llm-moderation";
const $ = (id) => document.getElementById(id);
let managementKey = "";
let config = {};
let records = [];
let nextCursor = "";
let activeQuery = "";
let connected = false;
const busyButtons = new Set();
const defaults = {
  enabled: true,
  primary_mode: "cpa",
  cpa_base_url: "",
  cpa_api_key: "",
  primary_endpoint: "",
  primary_api_key: "",
  primary_model: "",
  primary_timeout: 10,
  fallback_enabled: false,
  fallback_mode: "external",
  fallback_cpa_base_url: "",
  fallback_cpa_api_key: "",
  fallback_endpoint: "",
  fallback_api_key: "",
  fallback_model: "",
  fallback_timeout: 10,
  threshold: 80,
  failure_policy: "deny",
  log_dir: "./logs/llm-moderation",
};
const labels = {
  allow: "放行",
  block: "拦截",
  error_denied: "故障拒绝",
  error_allowed: "故障放行",
  canceled: "已取消",
  skipped: "跳过",
};
const errorLabels = {
  model_list_unavailable: "无法读取模型列表，请检查 CPA 内部地址和访问 Key。",
  review_timeout: "审核请求超时",
  review_http_error: "审核接口返回错误状态",
  review_transport_error: "审核接口连接失败",
  invalid_verdict_json: "审核模型没有返回有效 JSON",
  incomplete_or_refused_completion: "审核输出被截断或模型拒绝返回结果",
  audit_directory_unavailable: "审核日志目录无法访问",
  invalid_configuration: "审核配置无效",
  fallback_disabled: "尚未启用 fallback",
  "primary_timeout must be a number of seconds between 2 and 600":
    "主审核超时时间必须是 2–600 秒之间的数字。",
  "fallback_timeout must be a number of seconds between 2 and 600":
    "备用审核超时时间必须是 2–600 秒之间的数字。",
};

function notice(message, error = false) {
  $("notice").textContent = message;
  $("notice").className = "notice" + (error ? " error" : "");
  $("notice").hidden = !message;
}
function errorText(error) {
  return errorLabels[error.message] || error.message;
}
async function api(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    headers: {
      Authorization: "Bearer " + managementKey,
      "Content-Type": "application/json",
      ...(options.headers || {}),
    },
    cache: "no-store",
  });
  let data;
  try {
    data = await response.json();
  } catch {
    throw new Error("管理接口未返回 JSON，请检查 CPA 地址与插件状态。");
  }
  if (!response.ok) {
    if (response.status === 401 || response.status === 403)
      throw new Error("管理认证失败，请检查管理密钥。");
    throw new Error(
      typeof data.error === "string"
        ? data.error
        : data.message || "管理接口请求失败（" + response.status + "）",
    );
  }
  return data;
}
async function busy(button, action) {
  const old = button.textContent;
  busyButtons.add(button);
  button.disabled = true;
  try {
    await action();
  } catch (error) {
    notice(errorText(error), true);
  } finally {
    busyButtons.delete(button);
    button.disabled = false;
    button.textContent = old;
    modeFields();
  }
}
function selectedTab(name) {
  document.querySelectorAll(".tab").forEach((tab) => {
    const active = tab.dataset.tab === name;
    tab.classList.toggle("active", active);
    tab.setAttribute("aria-selected", String(active));
  });
  document
    .querySelectorAll(".tab-panel")
    .forEach((panel) => (panel.hidden = panel.id !== name));
}
function pct(value) {
  return (value * 100).toFixed(1) + "%";
}
function duration(value) {
  return Number.isFinite(value)
    ? value.toFixed(value < 10 ? 1 : 0) + " ms"
    : "—";
}
function stamp() {
  $("updated").textContent =
    "更新于 " + new Date().toLocaleTimeString("zh-CN", { hour12: false });
}

function legacyTimeoutSeconds(value) {
  if (typeof value === "number") return value;
  if (typeof value !== "string") return NaN;
  const text = value.trim();
  const pattern = /(\d+(?:\.\d*)?|\.\d+)(ns|us|µs|μs|ms|s|m|h)/gy;
  const units = {
    ns: 1e-9,
    us: 1e-6,
    µs: 1e-6,
    μs: 1e-6,
    ms: 0.001,
    s: 1,
    m: 60,
    h: 3600,
  };
  let seconds = 0,
    end = 0,
    match;
  while ((match = pattern.exec(text))) {
    seconds += Number(match[1]) * units[match[2]];
    end = pattern.lastIndex;
  }
  return end === text.length && end > 0 ? seconds : NaN;
}

function showModelSelection(id, model) {
  const select = $(id);
  select.replaceChildren();
  const option = document.createElement("option");
  option.value = model;
  option.textContent = model || "请先加载模型列表";
  select.append(option);
}

function displayConfig(value) {
  config = { ...defaults, ...value };
  for (const key of ["primary_timeout", "fallback_timeout"]) {
    const seconds = legacyTimeoutSeconds(config[key]);
    config[key] = Number.isFinite(seconds) ? seconds : "";
  }
  for (const key of Object.keys(defaults)) {
    const el = $(key);
    if (!el) continue;
    if (el.type === "checkbox") el.checked = Boolean(config[key]);
    else el.value = String(config[key] ?? "");
  }
  $("external_model").value = config.primary_model;
  showModelSelection("cpa_model", config.primary_model);
  showModelSelection("fallback_cpa_model", config.fallback_model);
  $("rule-threshold").textContent =
    config.threshold === 0
      ? "0 · 全部拦截"
      : config.threshold === 100
        ? "100 · 不因模型评分拦截"
        : "违规且置信度 > " + config.threshold;
  modeFields();
}
function modeFields() {
  const cpa = $("primary_mode").value === "cpa";
  $("cpa-fields").hidden = !cpa;
  $("external-fields").hidden = cpa;
  $("cpa-fields")
    .querySelectorAll("input,select,button")
    .forEach((el) => (el.disabled = !cpa || busyButtons.has(el)));
  $("external-fields")
    .querySelectorAll("input,select")
    .forEach((el) => (el.disabled = cpa));
  const fallbackEnabled = $("fallback_enabled").checked;
  const fallbackCPA = $("fallback_mode").value === "cpa";
  $("fallback_mode").disabled = !fallbackEnabled;
  $("fallback_timeout").disabled = !fallbackEnabled;
  $("fallback_timeout").parentElement.classList.toggle(
    "disabled",
    !fallbackEnabled,
  );
  $("fallback-cpa-fields").disabled = !fallbackEnabled || !fallbackCPA;
  $("fallback-external-fields").disabled = !fallbackEnabled || fallbackCPA;
  $("fallback-cpa-fields").hidden = !fallbackCPA;
  $("fallback-external-fields").hidden = fallbackCPA;
  $("fallback-cpa-fields")
    .querySelectorAll("input,select,button")
    .forEach(
      (el) =>
        (el.disabled = !fallbackEnabled || !fallbackCPA || busyButtons.has(el)),
    );
  $("fallback-external-fields")
    .querySelectorAll("input")
    .forEach((el) => (el.disabled = !fallbackEnabled || fallbackCPA));
  $("test-fallback").disabled =
    !fallbackEnabled || busyButtons.has($("test-fallback"));
}

function readTimeout(id, label) {
  const raw = $(id).value.trim();
  const seconds = Number(raw);
  if (raw === "" || !Number.isFinite(seconds) || seconds < 2 || seconds > 600) {
    throw new Error(label + "超时时间必须是 2–600 秒之间的数字。");
  }
  return seconds;
}

function collectConfig() {
  const value = { ...config };
  for (const key of Object.keys(defaults)) {
    const el = $(key);
    if (!el) continue;
    value[key] =
      el.type === "checkbox"
        ? el.checked
        : key === "threshold"
          ? Number(el.value)
          : el.value.trim();
  }
  value.primary_model =
    value.primary_mode === "cpa"
      ? $("cpa_model").value
      : $("external_model").value.trim();
  value.fallback_model =
    value.fallback_mode === "cpa"
      ? $("fallback_cpa_model").value
      : $("fallback_model").value.trim();
  value.primary_timeout = readTimeout("primary_timeout", "主审核");
  value.fallback_timeout = readTimeout("fallback_timeout", "备用审核");
  return value;
}

async function refreshHealth() {
  const health = await api(base + "/health");
  $("health").textContent = health.ready ? "审核已就绪" : "配置待完善";
  $("health").className = "badge " + (health.ready ? "success" : "warning");
  if (health.last_config_error)
    notice(
      "新的配置未生效，当前继续使用上次有效配置：" + health.last_config_error,
      true,
    );
  if (!health.ready)
    notice("插件已加载，但配置尚未就绪：" + health.config_error, true);
}
async function compatibility() {
  try {
    const host = await api("/v0/management/config");
    const enabled =
      host.upstream?.codex?.["response-steering"] ??
      host.codex?.["response-steering"] ??
      host.oauth?.providers?.codex?.["response-steering"] ??
      false;
    $("steering-status").textContent = enabled
      ? "检测到 response-steering=true，请在 CPA 配置中关闭后使用预检。"
      : "response-steering 已关闭。WebSocket 拒绝时关闭连接，判定状态和原因可在日志中查看。";
    $("steering-status").classList.toggle("invalid", enabled);
  } catch {
    $("steering-status").textContent =
      "请在 CPA 配置中确认 response-steering=false。";
  }
}

async function overview() {
  const to = new Date(),
    from = new Date(to - Number($("overview-period").value) * 3600000);
  const query = new URLSearchParams({
    from: from.toISOString(),
    to: to.toISOString(),
  });
  const data = await api(base + "/summary?" + query);
  $("metric-requests").textContent = data.requests.toLocaleString("zh-CN");
  $("metric-block").textContent = pct(data.block_rate);
  $("metric-fallback").textContent = pct(data.fallback_rate);
  $("metric-failure").textContent = pct(data.failure_rate);
  $("metric-block-count").textContent = data.blocked + " 个请求被拦截";
  $("metric-fallback-count").textContent = data.fallbacks + " 次启用备用审核";
  $("timings").replaceChildren();
  for (const [label, key] of [
    ["主审核", "primary"],
    ["Fallback", "fallback"],
    ["预检决策总耗时", "precheck"],
  ]) {
    const tr = document.createElement("tr");
    for (const value of [
      label,
      data[key].count,
      data[key].count ? duration(data[key].avg_ms) : "—",
      data[key].count ? duration(data[key].p50_ms) : "—",
      data[key].count ? duration(data[key].p95_ms) : "—",
    ]) {
      const td = document.createElement("td");
      td.textContent = String(value);
      tr.append(td);
    }
    $("timings").append(tr);
  }
  if (data.corrupt_lines)
    notice(
      "查询中跳过了 " + data.corrupt_lines + " 条损坏或未完整写入的日志。",
      true,
    );
  stamp();
}

function logQuery() {
  const period = $("log-period").value;
  let to = new Date(),
    from;
  if (period === "custom") {
    from = new Date($("filter-from").value);
    to = new Date($("filter-to").value);
    if (
      !Number.isFinite(+from) ||
      !Number.isFinite(+to) ||
      to < from ||
      to - from > 31 * 86400000
    )
      throw new Error("请选择有效的开始和结束时间，单次范围最多 31 天。");
  } else from = new Date(to - Number(period) * 3600000);
  return new URLSearchParams({
    from: from.toISOString(),
    to: to.toISOString(),
    key: $("filter-key").value.trim(),
    target_model: $("filter-target").value.trim(),
    review_model: $("filter-review").value.trim(),
    decision: $("filter-decision").value,
    limit: "50",
  }).toString();
}
function cell(text, className = "") {
  const td = document.createElement("td");
  td.textContent = text;
  td.className = className;
  return td;
}
function renderRecords() {
  $("records").replaceChildren();
  for (const record of records) {
    const tr = document.createElement("tr");
    const identity = cell(
      new Date(record.time).toLocaleString("zh-CN", { hour12: false }),
    );
    const key = document.createElement("span");
    key.className = "secondary mono";
    key.textContent =
      record.masked_key === "unavailable"
        ? record.key_fingerprint.slice(0, 16)
        : record.masked_key;
    key.title = record.key_fingerprint;
    identity.append(key);
    tr.append(identity);
    const model = cell(
      record.requested_model || record.target_model,
      "mono model-cell",
    );
    model.title = record.requested_model || record.target_model;
    tr.append(model);
    const status = cell("");
    const badge = document.createElement("span");
    badge.className =
      "badge " +
      ({
        allow: "success",
        block: "danger",
        error_denied: "danger",
        error_allowed: "warning",
        skipped: "neutral",
        canceled: "neutral",
      }[record.decision] || "neutral");
    badge.textContent = labels[record.decision] || record.decision;
    status.append(badge);
    tr.append(status);
    tr.append(
      cell(
        record.confidence == null ? "—" : record.confidence.toFixed(1),
        "mono",
      ),
    );
    const reviewer = cell(record.final_review_model || "—", "mono model-cell");
    reviewer.title = record.final_review_model || "";
    if (record.fallback_used) {
      const note = document.createElement("span");
      note.className = "secondary";
      note.textContent = "使用 fallback";
      reviewer.append(note);
    }
    tr.append(reviewer);
    tr.append(
      cell(
        duration(record.review_total_ms) +
          " / " +
          duration(record.precheck_duration_ms),
        "mono",
      ),
    );
    const detail = cell("");
    const button = document.createElement("button");
    button.className = "text-button";
    button.textContent = "详情";
    button.addEventListener("click", () => {
      $("detail-data").textContent = JSON.stringify(record, null, 2);
      $("detail").showModal();
    });
    detail.append(button);
    tr.append(detail);
    $("records").append(tr);
  }
  $("empty").hidden = records.length !== 0;
  $("record-count").textContent = "已显示 " + records.length + " 条记录";
  $("next-page").disabled = !nextCursor;
}
async function logs(append = false) {
  if (!append) {
    activeQuery = logQuery();
    records = [];
  }
  const data = await api(
    base +
      "/records?" +
      activeQuery +
      (append ? "&cursor=" + encodeURIComponent(nextCursor) : ""),
  );
  records = append ? records.concat(data.records) : data.records;
  nextCursor = data.next_cursor;
  renderRecords();
  if (data.corrupt_lines)
    notice(
      "查询中跳过了 " + data.corrupt_lines + " 条损坏或未完整写入的日志。",
      true,
    );
  stamp();
}

$("login-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = event.submitter;
  await busy(button, async () => {
    managementKey = $("management-key").value.trim();
    if (!managementKey) throw new Error("请输入管理密钥。");
    const value = await api(base + "/config");
    displayConfig(value);
    connected = true;
    $("management-key").value = "";
    $("login").hidden = true;
    $("workspace").hidden = false;
    $("lock").hidden = false;
    notice("");
    await Promise.all([refreshHealth(), overview(), compatibility()]);
  });
});
$("lock").addEventListener("click", () => {
  managementKey = "";
  connected = false;
  config = {};
  records = [];
  nextCursor = "";
  document
    .querySelectorAll('input[type="password"]')
    .forEach((input) => (input.value = ""));
  $("workspace").hidden = true;
  $("login").hidden = false;
  $("lock").hidden = true;
  $("health").textContent = "未连接";
  $("health").className = "badge neutral";
  notice("");
});
document.querySelectorAll(".tab").forEach((tab) =>
  tab.addEventListener("click", () => {
    selectedTab(tab.dataset.tab);
    if (tab.dataset.tab === "logs" && connected)
      logs().catch((error) => notice(errorText(error), true));
  }),
);
$("primary_mode").addEventListener("change", modeFields);
$("fallback_mode").addEventListener("change", modeFields);
$("fallback_enabled").addEventListener("change", modeFields);
async function loadModels(target, button) {
  await busy(button, async () => {
    const id = target === "fallback" ? "fallback_cpa_model" : "cpa_model";
    const connection = () =>
      target === "fallback"
        ? [$("fallback_cpa_base_url").value, $("fallback_cpa_api_key").value]
        : [$("cpa_base_url").value, $("cpa_api_key").value];
    const initialConnection = JSON.stringify(connection());
    const previous = $(id).value;
    const result = await api(base + "/models?target=" + target, {
      method: "POST",
      body: JSON.stringify(collectConfig()),
    });
    if (JSON.stringify(connection()) !== initialConnection) {
      notice("连接配置已变更，请重新刷新模型列表。", true);
      return;
    }
    $(id).replaceChildren();
    const placeholder = document.createElement("option");
    placeholder.value = "";
    placeholder.textContent = "选择审核模型";
    $(id).append(placeholder);
    for (const model of result.models) {
      const option = document.createElement("option");
      option.value = model.id;
      option.textContent = model.id;
      $(id).append(option);
    }
    if (result.models.some((model) => model.id === previous))
      $(id).value = previous;
    notice(
      (target === "fallback" ? "备用审核" : "主审核") +
        "已读取 " +
        result.models.length +
        " 个可用模型。",
    );
  });
}
$("load-models").addEventListener("click", (event) =>
  loadModels("primary", event.currentTarget),
);
$("load-fallback-models").addEventListener("click", (event) =>
  loadModels("fallback", event.currentTarget),
);
$("settings-form").addEventListener("submit", (event) => {
  event.preventDefault();
  busy($("save"), async () => {
    const value = collectConfig();
    if (
      !Number.isFinite(value.threshold) ||
      value.threshold < 0 ||
      value.threshold > 100
    )
      throw new Error("阈值必须在 0 到 100 之间。");
    await api(base + "/validate", {
      method: "POST",
      body: JSON.stringify(value),
    });
    await api(base + "/config", {
      method: "PATCH",
      body: JSON.stringify(value),
    });
    const stored = await api(base + "/config");
    displayConfig(stored);
    notice("配置已保存并回读确认。新请求将使用更新后的配置。");
    await refreshHealth();
  });
});
async function testReviewer(target, button) {
  await busy(button, async () => {
    const resultEl = $(target + "-result");
    const testedConfig = collectConfig();
    resultEl.textContent = "正在发送测试请求…";
    resultEl.className = "test-result";
    try {
      const result = await api(base + "/test", {
        method: "POST",
        body: JSON.stringify({ target, config: testedConfig }),
      });
      if (JSON.stringify(collectConfig()) !== JSON.stringify(testedConfig)) {
        resultEl.className = "test-result";
        resultEl.textContent = "测试期间配置已变更，请重新测试";
        return;
      }
      resultEl.className = "test-result " + (result.success ? "ok" : "fail");
      resultEl.textContent = result.success
        ? "通过 · " + duration(result.attempt.duration_ms)
        : "失败 · " +
          (errorLabels[result.attempt.error_code] ||
            result.attempt.error_code) +
          " · " +
          duration(result.attempt.duration_ms);
    } catch (error) {
      resultEl.textContent = "测试未完成";
      resultEl.className = "test-result fail";
      throw error;
    }
  });
}
$("test-primary").addEventListener("click", (event) =>
  testReviewer("primary", event.currentTarget),
);
$("test-fallback").addEventListener("click", (event) =>
  testReviewer("fallback", event.currentTarget),
);
$("refresh-overview").addEventListener("click", (event) =>
  busy(event.currentTarget, overview),
);
$("overview-period").addEventListener("change", () =>
  overview().catch((error) => notice(errorText(error), true)),
);
$("refresh-logs").addEventListener("click", (event) =>
  busy(event.currentTarget, () => logs()),
);
$("filters").addEventListener("submit", (event) => {
  event.preventDefault();
  busy(event.submitter, () => logs());
});
$("next-page").addEventListener("click", (event) =>
  busy(event.currentTarget, () => logs(true)),
);
$("log-period").addEventListener("change", () => {
  $("custom-times").hidden = $("log-period").value !== "custom";
});
$("close-detail").addEventListener("click", () => $("detail").close());
$("settings-form").addEventListener(
  "invalid",
  (event) => {
    if (
      event.target.id === "primary_timeout" ||
      event.target.id === "fallback_timeout"
    ) {
      const label =
        event.target.id === "primary_timeout" ? "主审核" : "备用审核";
      notice(label + "超时时间必须是 2–600 秒之间的数字。", true);
    }
  },
  true,
);
for (const eventName of ["input", "change"]) {
  $("settings-form").addEventListener(eventName, (event) => {
    const id = event.target.id;
    const target = /^(primary_|cpa_|external_)/.test(id)
      ? "primary"
      : id.startsWith("fallback_")
        ? "fallback"
        : "";
    if (!target) return;
    const result = $(target + "-result");
    result.className = "test-result";
    result.textContent = "配置已变更，待测试";
  });
}
