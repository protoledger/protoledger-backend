// Замер пути интерфейса на записи профиля: импорт в проект, прогон описания с гипотезами, отчёт.
// В отличие от `protoledger bench`, сюда входят копирование записи с sha256, задачи, сохранение прогона.
// Использование: node scripts/bench-api.mjs <protoledger> <запись> [--json <файл>] [--memory-gib <N>]
// --memory-gib ограничивает адресное пространство движка (prlimit, Linux), как память в профиле проверки.
// Пик памяти — VmHWM процесса движка (Linux); на других ОС — null.
import { spawn } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const [bin, capture] = process.argv.slice(2);
const option = (name) => (process.argv.includes(name) ? process.argv[process.argv.indexOf(name) + 1] : null);
const jsonOut = option("--json");
const memoryGib = Number(option("--memory-gib") ?? 0);
if (!bin || !capture) {
  console.error("использование: node scripts/bench-api.mjs <protoledger> <запись> [--json <файл>] [--memory-gib <N>]");
  process.exit(2);
}

const workspace = fs.mkdtempSync(path.join(os.tmpdir(), "pl-bench-"));
const port = 18474;
const base = `http://127.0.0.1:${port}`;
const serve = [path.resolve(bin), "serve", "--workspace", workspace, "--port", String(port)];
// prlimit запускает движок в том же процессе (exec), поэтому pid и VmHWM — движка.
const command = memoryGib > 0 ? ["prlimit", `--as=${memoryGib * 2 ** 30}`, "--", ...serve] : serve;
const server = spawn(command[0], command.slice(1), { stdio: "ignore" });
process.on("exit", () => {
  server.kill();
  fs.rmSync(workspace, { recursive: true, force: true });
});

let token = "";
async function api(method, url, body) {
  const response = await fetch(`${base}/api${url}`, {
    method,
    headers: { "X-Protoledger-Token": token, ...(body ? { "Content-Type": "application/json" } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await response.text();
  if (!response.ok) throw new Error(`${method} ${url}: ${response.status} ${text}`);
  return text ? JSON.parse(text) : null;
}

async function job(started) {
  for (;;) {
    const state = await api("GET", `/jobs/${started.jobId}`);
    if (state.state === "succeeded") return state.result;
    if (state.state !== "running" && state.state !== "queued") {
      throw new Error(`задача ${started.jobId}: ${JSON.stringify(state.error)}`);
    }
    await new Promise((r) => setTimeout(r, 20));
  }
}

async function timed(f) {
  const t = performance.now();
  const result = await f();
  return [Math.round(performance.now() - t), result];
}

function peakMemory() {
  try {
    const status = fs.readFileSync(`/proc/${server.pid}/status`, "utf8");
    const kib = Number(/^VmHWM:\s+(\d+)/m.exec(status)?.[1]);
    return Number.isFinite(kib) ? kib * 1024 : null;
  } catch {
    return null;
  }
}

for (let i = 0; ; i++) {
  try {
    if ((await fetch(`${base}/api/health`)).ok) break;
  } catch {}
  if (i > 200) throw new Error("движок не запустился");
  await new Promise((r) => setTimeout(r, 50));
}
token = /protoledger-token" content="([^"]+)"/.exec(await (await fetch(`${base}/`)).text())?.[1] ?? "";

// Сообщения записи профиля: [A5][тип][длина тела u16 BE][тело]; ответ — тип запроса + 0x80.
const interpretation = `format: protoledger/interpretation@1
framing:
  kind: length_prefixed
  length: { at: 2, type: u16be, adjust: 4 }
  status: rule
messages:
  - id: request
    when: "kind < 0x80"
    fields:
      - { name: magic, at: 0, type: u8, expect: 0xA5, status: rule }
      - { name: kind, at: 1, type: u8, status: hypothesis, hypothesis: H1 }
      - { name: len, at: 2, type: u16be, status: rule }
  - id: response
    when: "kind >= 0x80"
    fields:
      - { name: magic, at: 0, type: u8, expect: 0xA5, status: rule }
      - { name: kind, at: 1, type: u8, status: hypothesis, hypothesis: H1 }
      - { name: len, at: 2, type: u16be, status: rule }
hypotheses:
  - { id: H1, statement: "ответ повторяет тип запроса со старшим битом", test: "kind + 0x80 == response.kind" }
  - { id: H2, statement: "сигнатура ответа та же", test: "magic == response.magic" }
`;

await api("POST", "/project", { path: "bench.protoledger", mode: "create" });
const size = fs.statSync(capture).size;
const [importMs, imported] = await timed(async () =>
  job(await api("POST", "/sources", { path: path.resolve(capture) })),
);
await api("PUT", "/interpretation", { yaml: interpretation });
const [runMs] = await timed(async () => job(await api("POST", "/runs", {})));
const run = await api("GET", "/runs/run-0001");
const [reportMdMs, md] = await timed(() => api("POST", "/reports", { format: "md" }));
const [reportHtmlMs] = await timed(() => api("POST", "/reports", { format: "html" }));
const connections = (await api("GET", `/connections?source=${imported.sourceSha256}&limit=1`)).total;

const result = {
  captureBytes: size,
  connections,
  messages: run.summary.messages,
  hypotheses: run.hypotheses.map((h) => ({ id: h.id, verdict: h.verdict })),
  timings: { importMs, runMs, reportMdMs, reportHtmlMs },
  reportBytes: md.content.length,
  peakMemoryBytes: peakMemory(),
};
if (jsonOut) fs.writeFileSync(jsonOut, JSON.stringify(result, null, 2));

const mib = (b) => (b / 2 ** 20).toFixed(1).replace(".", ",");
const s = (ms) => `${(ms / 1000).toFixed(2).replace(".", ",")} с`;
const verdicts = { no_counterexample: "контрпримеров нет", refuted: "опровергнута" };
console.log(`| Операция через API | Время |
|---|---|
| Импорт записи ${mib(size)} МиБ в проект (копия, sha256, индекс, ${connections} соединений) | ${s(importMs)} |
| Прогон описания: ${run.summary.messages} сообщений, гипотезы ${result.hypotheses.map((h) => `${h.id} — ${verdicts[h.verdict] ?? h.verdict}`).join(", ")} | ${s(runMs)} |
| Отчёт Markdown | ${s(reportMdMs)} |
| Отчёт HTML | ${s(reportHtmlMs)} |

Пик памяти движка: ${result.peakMemoryBytes === null ? "недоступен (нет /proc)" : `${mib(result.peakMemoryBytes)} МиБ`}.`);
process.exit(0);
