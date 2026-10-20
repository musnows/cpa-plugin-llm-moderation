import fs from "node:fs";
import path from "node:path";
import net from "node:net";
import { spawn } from "node:child_process";

const [project, cpaBinary, work] = process.argv.slice(2);
if (!project || !cpaBinary || !work)
  throw new Error("Usage: launch.mjs PROJECT CPA_BINARY WORK_DIRECTORY");
fs.mkdirSync(work, { recursive: true });
const goOS = process.platform === "win32" ? "windows" : process.platform;
const goArch = process.arch === "x64" ? "amd64" : process.arch;
async function portFrom(start) {
  for (let port = start; port < start + 100; port++) {
    const free = await new Promise((resolve) => {
      const server = net.createServer();
      server.once("error", () => resolve(false));
      server.listen(port, "127.0.0.1", () => server.close(() => resolve(true)));
    });
    if (free) return port;
  }
  throw new Error("No test port available");
}
const mockPort = await portFrom(19080),
  cpaPort = await portFrom(mockPort + 10);
const mockURL = `http://127.0.0.1:${mockPort}`,
  cpaURL = `http://127.0.0.1:${cpaPort}`;
const runtime = {
  cpa_url: cpaURL,
  mock_url: mockURL,
  client_key: "fixture-client-key-2026-001",
  review_key: "fixture-review-key-2026-002",
  fallback_review_key: "fixture-fallback-cpa-key-2026-003",
  management_key: "fixture-management-key-2026",
  work,
};
const config = {
  host: "127.0.0.1",
  port: cpaPort,
  "auth-dir": path.join(work, "auth"),
  "api-keys": [
    runtime.client_key,
    runtime.review_key,
    runtime.fallback_review_key,
  ],
  "remote-management": {
    "allow-remote": false,
    "secret-key": runtime.management_key,
    "disable-control-panel": true,
  },
  "request-retry": 0,
  "max-retry-interval": 0,
  "logging-to-file": false,
  "request-log": false,
  "usage-statistics-enabled": false,
  "websocket-auth": true,
  codex: { "response-steering": false },
  "openai-compatibility": [
    {
      name: "fixture",
      "base-url": mockURL + "/v1",
      "request-retry": 0,
      "api-key-entries": [{ "api-key": "fixture-upstream-key" }],
      models: [
        "target-model",
        "review-via-cpa",
        "review-block",
        "review-slow",
        "review-timeout",
      ].map((name) => ({ name, alias: name, thinking: { levels: ["none"] } })),
    },
  ],
  plugins: {
    enabled: true,
    dir: path.join(project, "artifacts", goOS, goArch),
    configs: {
      "llm-moderation": {
        enabled: true,
        priority: 1,
        primary_mode: "external",
        primary_endpoint: mockURL + "/review/chat/completions",
        primary_api_key: "fixture-primary-review-key",
        primary_model: "review-safe",
        primary_timeout: 10,
        cpa_base_url: cpaURL,
        cpa_api_key: runtime.review_key,
        fallback_enabled: true,
        fallback_mode: "external",
        fallback_cpa_base_url: cpaURL,
        fallback_cpa_api_key: runtime.fallback_review_key,
        fallback_endpoint: mockURL + "/fallback/chat/completions",
        fallback_api_key: "fixture-fallback-review-key",
        fallback_model: "review-safe",
        fallback_timeout: 10,
        threshold: 80,
        failure_policy: "deny",
        prompt_mode: "append",
        append_prompt: "",
        override_prompt: "",
        log_dir: path.join(work, "audit"),
      },
    },
  },
};
runtime.default_config = config.plugins.configs["llm-moderation"];
fs.writeFileSync(
  path.join(work, "runtime.json"),
  JSON.stringify(runtime, null, 2),
);
fs.writeFileSync(
  path.join(work, "config.yaml"),
  JSON.stringify(config, null, 2),
);
const children = [];
function start(binary, args, log) {
  const fd = fs.openSync(path.join(work, log), "a");
  const child = spawn(binary, args, { cwd: work, stdio: ["ignore", fd, fd] });
  children.push(child);
  return child;
}
start(
  path.join(
    project,
    "artifacts",
    process.platform === "win32" ? "mockserver.exe" : "mockserver",
  ),
  ["-port", String(mockPort), "-state", path.join(work, "mock-state.json")],
  "mock.log",
);
start(
  cpaBinary,
  ["-config", path.join(work, "config.yaml"), "-local-model"],
  "cpa.log",
);
console.log("Test services started: " + cpaURL + " and " + mockURL);
let stopping = false;
function stop() {
  if (stopping) return;
  stopping = true;
  for (const child of children) child.kill("SIGTERM");
  setTimeout(() => process.exit(0), 1500).unref();
}
process.on("SIGTERM", stop);
process.on("SIGINT", stop);
for (const child of children)
  child.once("exit", (code) => {
    if (!stopping) {
      console.error("Test service exited with code " + code);
      stop();
    }
  });
