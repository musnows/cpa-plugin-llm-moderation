import fs from "node:fs";
import assert from "node:assert/strict";
import { performance } from "node:perf_hooks";
import { createHash } from "node:crypto";

const runtime = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
const base = runtime.cpa_url,
  management = base + "/v0/management/plugins/llm-moderation";
const results = [];
const pause = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
async function json(url, options = {}) {
  const response = await fetch(url, options);
  const body = await response.text();
  let data;
  try {
    data = JSON.parse(body);
  } catch {
    data = body;
  }
  return { status: response.status, data };
}
const admin = (url, options = {}) =>
  json(url, {
    ...options,
    headers: {
      Authorization: "Bearer " + runtime.management_key,
      "Content-Type": "application/json",
      ...options.headers,
    },
  });
async function configure(patch) {
  const cfg = { ...runtime.default_config, ...patch };
  let r = await admin(management + "/config", {
    method: "PATCH",
    body: JSON.stringify(cfg),
  });
  assert.equal(r.status, 200, JSON.stringify(r.data));
  for (let i = 0; i < 80; i++) {
    r = await admin(management + "/health");
    if (
      r.status === 200 &&
      r.data.ready &&
      Object.entries(cfg).every(
        ([key, value]) =>
          key.endsWith("api_key") ||
          key === "priority" ||
          r.data.active_config[key] === value,
      )
    )
      return cfg;
    await pause(100);
  }
  throw new Error("Configuration did not become active");
}
const events = () =>
  json(runtime.mock_url + "/events").then((r) => r.data || []);
const targetCount = async () =>
  (await events()).filter((e) => e.kind === "target").length;
const reviewCount = async () =>
  (await events()).filter((e) => e.kind === "review").length;
async function chat(text, extra = {}, headers = {}) {
  return json(base + "/v1/chat/completions", {
    method: "POST",
    headers: {
      Authorization: "Bearer " + runtime.client_key,
      "Content-Type": "application/json",
      ...headers,
    },
    body: JSON.stringify({
      model: "target-model",
      messages: [{ role: "user", content: text }],
      ...extra,
    }),
  });
}
async function test(name, action) {
  if (process.env.CPA_TEST_SKIP && name.includes(process.env.CPA_TEST_SKIP)) {
    results.push({ name, skipped: true });
    console.log("SKIP " + name);
    return;
  }
  const start = performance.now();
  await action();
  results.push({ name, passed: true, duration_ms: performance.now() - start });
  console.log("PASS " + name);
}
async function lastRecords() {
  const r = await admin(management + "/records?limit=200");
  assert.equal(r.status, 200);
  return r.data.records;
}
async function websocket(text, acceptClose = false) {
  return new Promise((resolve, reject) => {
    const url =
      base.replace("http", "ws") +
      "/v1/responses?key=" +
      encodeURIComponent(runtime.client_key);
    const ws = new WebSocket(url);
    const collected = [];
    const timer = setTimeout(() => {
      ws.close();
      reject(new Error("WebSocket timed out: " + JSON.stringify(collected)));
    }, 10000);
    ws.onopen = () =>
      ws.send(
        JSON.stringify({
          type: "response.create",
          model: "target-model",
          input: [{ role: "user", content: [{ type: "input_text", text }] }],
        }),
      );
    ws.onmessage = (event) => {
      const data = JSON.parse(event.data);
      collected.push(data);
      if (data.type === "error" || data.type === "response.completed") {
        clearTimeout(timer);
        ws.close();
        resolve(collected);
      }
    };
    ws.onerror = () => {
      if (acceptClose) return;
      clearTimeout(timer);
      reject(new Error("WebSocket connection failed"));
    };
    ws.onclose = () => {
      if (acceptClose) {
        clearTimeout(timer);
        resolve(collected);
      }
    };
  });
}

try {
  await test("plugin registration and protected resources", async () => {
    const plugins = await admin(base + "/v0/management/plugins");
    assert.equal(plugins.status, 200);
    const plugin = plugins.data.plugins.find(
      (item) => item.id === "llm-moderation",
    );
    assert.ok(plugin?.registered && plugin?.effective_enabled);
    assert.equal((await json(management + "/records")).status, 401);
    const html = await fetch(
      base + "/v0/resource/plugins/llm-moderation/dashboard",
    ).then((r) => r.text());
    assert.ok(html.includes("LLM 输入预检"));
    assert.ok(!html.includes(runtime.client_key));
  });
  await configure({});
  await test("safe request reaches target exactly once", async () => {
    const before = await targetCount();
    const result = await chat("TEST_SAFE");
    assert.equal(result.status, 200, JSON.stringify(result.data));
    assert.equal(await targetCount(), before + 1);
  });
  await test("violating request is HTTP 403 and never reaches target", async () => {
    const before = await targetCount();
    const result = await chat("TEST_BLOCK");
    assert.equal(result.status, 403, JSON.stringify(result.data));
    assert.equal(result.data.error.code, "content_policy_violation");
    assert.equal(await targetCount(), before);
  });
  await test("SSE violation returns HTTP 403 before streaming", async () => {
    const before = await targetCount();
    const result = await chat("TEST_BLOCK", { stream: true });
    assert.equal(result.status, 403);
    assert.equal(await targetCount(), before);
  });
  await test("Responses, Claude and Gemini inputs are moderated", async () => {
    const before = await targetCount();
    for (const [path, body] of [
      ["/v1/responses", { model: "target-model", input: "TEST_BLOCK" }],
      [
        "/v1/messages",
        {
          model: "target-model",
          max_tokens: 64,
          messages: [
            { role: "user", content: [{ type: "text", text: "TEST_BLOCK" }] },
          ],
        },
      ],
      [
        "/v1beta/models/target-model:generateContent",
        { contents: [{ role: "user", parts: [{ text: "TEST_BLOCK" }] }] },
      ],
    ]) {
      const r = await json(base + path, {
        method: "POST",
        headers: {
          Authorization: "Bearer " + runtime.client_key,
          "Content-Type": "application/json",
          "anthropic-version": "2023-06-01",
        },
        body: JSON.stringify(body),
      });
      assert.equal(r.status, 403, path + " " + JSON.stringify(r.data));
      const allowed = await json(base + path, {
        method: "POST",
        headers: {
          Authorization: "Bearer " + runtime.client_key,
          "Content-Type": "application/json",
          "anthropic-version": "2023-06-01",
        },
        body: JSON.stringify(body).replaceAll("TEST_BLOCK", "TEST_SAFE"),
      });
      assert.equal(
        allowed.status,
        200,
        path + " " + JSON.stringify(allowed.data),
      );
    }
    assert.equal(await targetCount(), before + 3);
  });
  await test("WebSocket safe generation and blocked upstream dispatch", async () => {
    const frames = await websocket("TEST_SAFE");
    assert.ok(frames.some((frame) => frame.type === "response.completed"));
    const before = await targetCount();
    await websocket("TEST_BLOCK", true);
    assert.equal(await targetCount(), before);
    const record = (await lastRecords())[0];
    assert.equal(record.decision, "block");
    assert.equal(record.protocol, "openai-response");
  });
  await test("WebSocket rejection closes connection and retains audit status", async () => {
    const before = await targetCount();
    const frames = await websocket("TEST_BLOCK", true);
    assert.ok(!frames.some((frame) => frame.type === "response.completed"));
    assert.equal(await targetCount(), before);
    const record = (await lastRecords())[0];
    assert.equal(record.decision_status, 403);
    assert.equal(record.error_code, "content_policy_violation");
    assert.ok(record.reason);
  });
  await test("strict threshold equality and safe confidence", async () => {
    assert.equal((await chat("TEST_BOUNDARY")).status, 200);
    assert.equal((await chat("TEST_SAFE_HIGH")).status, 200);
  });
  await test("threshold zero performs no review", async () => {
    await configure({ threshold: 0 });
    const reviews = await reviewCount(),
      targets = await targetCount();
    assert.equal((await chat("TEST_SAFE")).status, 403);
    assert.equal(await reviewCount(), reviews);
    assert.equal(await targetCount(), targets);
    const record = (await lastRecords())[0];
    assert.equal(record.confidence, null);
    assert.equal(record.review_total_ms, 0);
  });
  await test("threshold 100 permits score-based violations", async () => {
    await configure({ threshold: 100 });
    assert.equal((await chat("TEST_BLOCK")).status, 200);
  });
  await test("invalid JSON triggers exactly one fallback", async () => {
    await configure({ primary_model: "review-invalid" });
    const before = await reviewCount();
    assert.equal((await chat("TEST_SAFE")).status, 200);
    assert.equal(await reviewCount(), before + 2);
    const record = (await lastRecords())[0];
    assert.equal(record.final_reviewer, "fallback");
    assert.equal(record.attempts.length, 2);
  });
  await test("timeout cancels primary before fallback", async () => {
    await configure({
      primary_model: "review-timeout",
      primary_timeout: 2,
    });
    const start = performance.now();
    assert.equal((await chat("TEST_SAFE")).status, 200);
    const elapsed = performance.now() - start;
    assert.ok(elapsed >= 1900 && elapsed < 5000, "elapsed=" + elapsed);
    const recent = (await events()).slice(-5);
    const canceled = recent.findIndex((e) => e.kind === "review_canceled"),
      fallback = recent.findIndex(
        (e) => e.model === "review-safe" && e.kind === "review",
      );
    assert.ok(canceled >= 0 && fallback > canceled, JSON.stringify(recent));
    const record = (await lastRecords())[0];
    assert.ok(record.primary_duration_ms >= 1900);
    assert.ok(record.fallback_duration_ms > 0);
  });
  await test("both failures deny with 503 or explicitly allow", async () => {
    await configure({
      primary_model: "review-fail",
      fallback_model: "review-fail",
    });
    const before = await targetCount();
    assert.equal((await chat("TEST_SAFE")).status, 503);
    assert.equal(await targetCount(), before);
    await websocket("TEST_SAFE", true);
    assert.equal(await targetCount(), before);
    assert.equal((await lastRecords())[0].decision_status, 503);
    await configure({
      primary_model: "review-fail",
      fallback_model: "review-fail",
      failure_policy: "allow",
    });
    assert.equal((await chat("TEST_SAFE")).status, 200);
    assert.equal((await lastRecords())[0].decision, "error_allowed");
  });
  await test("CPA model selection and internal recursion guard", async () => {
    await configure({ primary_mode: "cpa", primary_model: "review-via-cpa" });
    const modelList = await admin(management + "/models");
    assert.equal(modelList.status, 200, JSON.stringify(modelList.data));
    assert.ok(modelList.data.models.some((x) => x.id === "review-via-cpa"));
    const before = await reviewCount(),
      records = (await lastRecords()).length;
    assert.equal((await chat("TEST_SAFE")).status, 200);
    assert.equal(await reviewCount(), before + 1);
    assert.equal((await lastRecords()).length, records + 1);
    assert.equal((await chat("TEST_BLOCK")).status, 403);
    const observed = (await events()).filter(
      (x) => x.kind === "review" && x.model === "review-via-cpa",
    );
    assert.ok(
      observed.every((x) => !x.nonce),
      "internal nonce forwarded upstream",
    );
  });
  await test("forged internal marker cannot bypass", async () => {
    await configure({});
    const before = await targetCount();
    assert.equal(
      (await chat("TEST_BLOCK", {}, { "X-CPA-Moderation-Nonce": "forged" }))
        .status,
      403,
    );
    assert.equal(await targetCount(), before);
  });
  await test("external primary can fail over to a CPA model", async () => {
    await configure({
      primary_model: "review-fail",
      fallback_mode: "cpa",
      fallback_model: "review-via-cpa",
    });
    const catalog = await admin(management + "/models?target=fallback");
    assert.equal(catalog.status, 200);
    assert.ok(
      catalog.data.models.some((model) => model.id === "review-via-cpa"),
    );
    const probe = await admin(management + "/test", {
      method: "POST",
      body: JSON.stringify({ target: "fallback" }),
    });
    assert.equal(probe.data.success, true);
    assert.equal(probe.data.attempt.model, "review-via-cpa");
    const before = await reviewCount();
    const totalBefore = (await admin(management + "/summary")).data.requests;
    assert.equal((await chat("TEST_SAFE")).status, 200);
    assert.equal(await reviewCount(), before + 2);
    assert.equal(
      (await admin(management + "/summary")).data.requests,
      totalBefore + 1,
    );
    const record = (await lastRecords())[0];
    assert.equal(record.final_reviewer, "fallback");
    assert.equal(record.final_review_model, "review-via-cpa");
    assert.equal(record.attempts.length, 2);
    const observed = (await events()).filter(
      (event) => event.model === "review-via-cpa" && event.kind === "review",
    );
    assert.ok(observed.every((event) => !event.nonce));
    assert.equal((await chat("TEST_BLOCK")).status, 403);
  });
  await test("CPA primary and CPA fallback remain independently routed", async () => {
    await configure({
      primary_mode: "cpa",
      primary_model: "review-timeout",
      primary_timeout: 2,
      fallback_mode: "cpa",
      fallback_model: "review-via-cpa",
    });
    const before = await reviewCount();
    assert.equal((await chat("TEST_SAFE")).status, 200);
    assert.equal(await reviewCount(), before + 2);
    const record = (await lastRecords())[0];
    assert.equal(record.attempts[0].model, "review-timeout");
    assert.equal(record.attempts[0].error_code, "review_timeout");
    assert.equal(record.attempts[1].model, "review-via-cpa");
    assert.equal(record.final_reviewer, "fallback");
  });
  await test("numeric timeout boundaries save and invalid values do not write", async () => {
    for (const boundary of [2, 600]) {
      await configure({
        primary_timeout: boundary,
        fallback_timeout: boundary,
      });
      const saved = await admin(management + "/config");
      assert.equal(saved.data.primary_timeout, boundary);
      assert.equal(saved.data.fallback_timeout, boundary);
    }
    const before = (await admin(management + "/config")).data;
    for (const field of ["primary_timeout", "fallback_timeout"]) {
      for (const value of [
        0,
        1.999,
        600.001,
        601,
        null,
        true,
        "10s",
        "10",
        "5m",
        "",
      ]) {
        const result = await admin(management + "/validate", {
          method: "POST",
          body: JSON.stringify({ ...before, [field]: value }),
        });
        assert.equal(result.status, 400, field + "=" + String(value));
      }
    }
    assert.deepEqual((await admin(management + "/config")).data, before);
    await configure({});
  });
  await test("legacy timeout strings load with the external fallback default", async () => {
    const updated = await admin(management + "/config", {
      method: "PATCH",
      body: JSON.stringify({
        primary_timeout: "10s",
        fallback_timeout: "30s",
        fallback_mode: null,
      }),
    });
    assert.equal(updated.status, 200);
    let state;
    for (let i = 0; i < 40; i++) {
      state = (await admin(management + "/health")).data;
      if (state.active_config.fallback_timeout === 30) break;
      await pause(100);
    }
    assert.equal(state.active_config.primary_timeout, 10);
    assert.equal(state.active_config.fallback_timeout, 30);
    assert.equal(state.active_config.fallback_mode, "external");
    await configure({});
  });
  await test("prompt template requires management authentication", async () => {
    assert.equal((await json(management + "/prompt")).status, 401);
    const template = await admin(management + "/prompt");
    assert.equal(template.status, 200);
    assert.ok(template.data.system_prompt.includes("user_messages"));
    assert.ok(template.data.system_prompt.includes('"is_violation"'));
  });
  for (const mode of ["append", "override"]) {
    await test(
      mode + " prompt reaches primary, fallback and reviewer probes",
      async () => {
        const template = (await admin(management + "/prompt")).data
          .system_prompt;
        const extra =
          "Apply the configured review rules consistently.\nPreserve the verdict JSON format.";
        const custom = "Custom review policy for this fixture.\n" + template;
        const cfg = await configure({
          prompt_mode: mode,
          append_prompt: extra,
          override_prompt: custom,
          primary_model: "review-invalid",
        });
        const effective =
          mode === "override"
            ? custom
            : template + "\n\nAdditional review instructions:\n" + extra;
        const hash = createHash("sha256").update(effective).digest("hex");
        const before = (await events()).length;
        assert.equal((await chat("TEST_SAFE")).status, 200);
        const calls = (await events())
          .slice(before)
          .filter((item) => item.kind === "review");
        assert.equal(calls.length, 2);
        assert.ok(calls.every((item) => item.system_prompt_sha256 === hash));
        const record = (await lastRecords())[0];
        assert.equal(record.prompt_mode, mode);
        assert.equal(record.prompt_sha256, hash);
        assert.ok(!JSON.stringify(record).includes(extra));
        for (const target of ["primary", "fallback"]) {
          const start = (await events()).length;
          const probe = await admin(management + "/test", {
            method: "POST",
            body: JSON.stringify({
              target,
              config: { ...cfg, primary_model: "review-safe" },
            }),
          });
          assert.equal(probe.data.success, true);
          assert.equal(
            (await events()).slice(start).find((item) => item.kind === "review")
              .system_prompt_sha256,
            hash,
          );
        }
        await configure({});
      },
    );
  }
  await test("invalid prompt settings are rejected before save", async () => {
    const before = (await admin(management + "/config")).data;
    for (const patch of [
      { prompt_mode: "invalid" },
      { prompt_mode: "override", override_prompt: " \n" },
      { append_prompt: 3 },
    ]) {
      const result = await admin(management + "/validate", {
        method: "POST",
        body: JSON.stringify({ ...runtime.default_config, ...patch }),
      });
      assert.equal(result.status, 400);
    }
    assert.deepEqual((await admin(management + "/config")).data, before);
  });
  await test("configuration validation preserves active policy", async () => {
    const bad = await admin(management + "/validate", {
      method: "POST",
      body: JSON.stringify({ ...runtime.default_config, threshold: 101 }),
    });
    assert.equal(bad.status, 400);
    assert.equal((await chat("TEST_BLOCK")).status, 403);
  });
  await test("invalid native config cannot unregister the interceptor", async () => {
    const bad = await admin(management + "/config", {
      method: "PATCH",
      body: JSON.stringify({ threshold: 101 }),
    });
    assert.equal(bad.status, 200);
    let health;
    for (let i = 0; i < 40; i++) {
      health = await admin(management + "/health");
      if (health.data.last_config_error) break;
      await pause(100);
    }
    assert.equal(health.status, 200);
    assert.ok(health.data.last_config_error);
    assert.equal(health.data.active_config.threshold, 80);
    assert.equal((await chat("TEST_BLOCK")).status, 403);
    await configure({});
  });
  await test("client disconnect cancels review without fallback", async () => {
    await configure({ primary_model: "review-timeout" });
    const before = (await events()).length;
    const controller = new AbortController();
    const request = fetch(base + "/v1/chat/completions", {
      method: "POST",
      signal: controller.signal,
      headers: {
        Authorization: "Bearer " + runtime.client_key,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        model: "target-model",
        messages: [{ role: "user", content: "TEST_SAFE" }],
      }),
    }).catch(() => null);
    for (let i = 0; i < 30; i++) {
      if ((await events()).slice(before).some((x) => x.kind === "review"))
        break;
      await pause(10);
    }
    controller.abort();
    await request;
    let observed;
    for (let i = 0; i < 40; i++) {
      observed = (await events()).slice(before);
      if (observed.some((x) => x.kind === "review_canceled")) break;
      await pause(25);
    }
    assert.ok(observed.some((x) => x.kind === "review_canceled"));
    await pause(80);
    assert.equal(
      (await events()).slice(before).filter((x) => x.kind === "review").length,
      1,
    );
    assert.equal((await lastRecords())[0].decision, "canceled");
    await configure({});
  });
  await test("logs contain identity, model and timings without secrets", async () => {
    const list = await lastRecords();
    assert.ok(list.length > 10);
    assert.ok(
      list.every((r) => r.target_model && r.key_fingerprint !== "unidentified"),
    );
    const text = JSON.stringify(list);
    for (const secret of [
      runtime.client_key,
      runtime.review_key,
      runtime.fallback_review_key,
      "fixture-primary-review-key",
      "fixture-fallback-review-key",
      "TEST_BLOCK",
      "TEST_SAFE",
    ]) {
      assert.ok(!text.includes(secret), "leaked " + secret);
    }
    const summary = await admin(management + "/summary");
    assert.equal(summary.status, 200);
    assert.ok(summary.data.primary.count > 0);
    assert.ok(summary.data.fallback.count > 0);
  });
  await test("latency comparison", async () => {
    const measured = {};
    for (const [name, cfg] of [
      ["disabled", null],
      ["primary", { primary_model: "review-slow" }],
      [
        "fallback",
        { primary_model: "review-fail", fallback_model: "review-slow" },
      ],
    ]) {
      if (cfg) await configure(cfg);
      else {
        await admin(management + "/enabled", {
          method: "PATCH",
          body: JSON.stringify({ enabled: false }),
        });
        await pause(500);
      }
      const times = [];
      for (let i = 0; i < 5; i++) {
        const start = performance.now();
        const response = await fetch(base + "/v1/chat/completions", {
          method: "POST",
          headers: {
            Authorization: "Bearer " + runtime.client_key,
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            model: "target-model",
            stream: true,
            messages: [{ role: "user", content: "TEST_SAFE" }],
          }),
        });
        assert.equal(response.status, 200);
        const reader = response.body.getReader();
        await reader.read();
        times.push(performance.now() - start);
        while (!(await reader.read()).done) {}
      }
      times.sort((a, b) => a - b);
      measured[name] = { median_first_chunk_ms: times[2], samples_ms: times };
    }
    assert.ok(
      measured.primary.median_first_chunk_ms >
        measured.disabled.median_first_chunk_ms + 80,
    );
    fs.writeFileSync(
      runtime.work + "/latency.json",
      JSON.stringify(measured, null, 2),
    );
  });
  await configure({
    primary_mode: "cpa",
    primary_model: "review-via-cpa",
    fallback_mode: "cpa",
    fallback_model: "review-via-cpa",
  });
  fs.writeFileSync(
    runtime.work + "/integration-results.json",
    JSON.stringify(
      {
        passed: results.every((item) => item.passed),
        passed_count: results.filter((item) => item.passed).length,
        skipped_count: results.filter((item) => item.skipped).length,
        tests: results,
      },
      null,
      2,
    ),
  );
  console.log(
    "Integration checks: " +
      results.filter((item) => item.passed).length +
      " passed, " +
      results.filter((item) => item.skipped).length +
      " skipped",
  );
} catch (error) {
  fs.writeFileSync(
    runtime.work + "/integration-results.json",
    JSON.stringify(
      {
        passed: false,
        tests: results,
        error: String(error),
        stack: error.stack,
      },
      null,
      2,
    ),
  );
  console.error(error);
  process.exitCode = 1;
}
