#!/usr/bin/env node
// ISO A.8.8 — agente de remediação de vulnerabilidades técnicas (npm audit).
//
// Loop ISO (A.8.8 — Gestão de vulnerabilidades técnicas):
//   1. Varre projetos npm sob a raiz (default ~/r), roda `npm audit --json`.
//   2. Reconcilia contra os riscos ABERTOS de dependência da org no /adm:
//        - pacote sumiu do audit  → RESOLVIDO → fecha o risco com evidência
//          ("npm audit sem vuln p/ <pkg> em <data>", autoria do agente).
//        - pacote ainda no audit   → PENDENTE → nota de pendência (não fecha).
//        - vuln high/critical sem risco aberto → abre risco (source=auto, A.8.8).
//        - low/moderate → contam como evidência no snapshot.
//   3. Grava 1 evidence-snapshot por rodada (resumo do audit) no A.8.8.
//
// Auth (default = SEM FRICÇÃO): sem token cacheado, faz AUTO-REGISTRO de avaliação
// — cria uma organização nova e isolada com o seu e-mail (git config user.email ou
// EXP_AGENT_EMAIL) como owner, e já começa a trabalhar. Depois você acessa o painel
// via magic-link com esse e-mail. Para conectar a uma conta EXISTENTE use --connect
// (device flow, aprovado pelo owner no /adm). Token cacheado em
// ~/.config/exponencial-agent/<org>.json. NUNCA é super-admin (só compliance:write na org dele).
//
// Modelo: a skill roda DENTRO do projeto/código (o cwd já tem package.json). A ORG
// vem do token; o PROJETO vem do cwd. Por padrão audita o projeto do cwd (sobe até
// o package-lock.json mais próximo). --scan-root <dir> varre vários projetos.
//
// Uso (rodar dentro do repo do projeto):
//   node remediate.mjs                 # auto-registra trial (se preciso) + audita + reconcilia
//   node remediate.mjs --connect       # conecta a uma conta existente (device flow)
//   node remediate.mjs --auth-only     # só garante o token
//   node remediate.mjs --dry-run       # mostra o plano, não escreve no /adm
//   node remediate.mjs --scan-root <d> # (opcional) varre vários projetos sob <d>
// Env:
//   EXP_ADMIN_BASE   (default https://exponencialadm.net)
//   EXP_AGENT_EMAIL  (opcional)              e-mail p/ o auto-registro (senão usa git config)
//   EXP_AGENT_ORG    (default exponencial)   org-alvo (normalmente vem do token)
//   EXP_AGENT_TOKEN  (opcional)              injeta token e pula registro/device flow

import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { readFile, writeFile, mkdir, readdir, stat } from "node:fs/promises";
import { existsSync } from "node:fs";
import path from "node:path";
import os from "node:os";

const pexec = promisify(execFile);
const BASE = (process.env.EXP_ADMIN_BASE || "https://exponencialadm.net").replace(/\/$/, "");
const argv = process.argv.slice(2);
const ARGS = new Set(argv);
const DRY = ARGS.has("--dry-run");
// --scan-root <dir> opcional: varre vários projetos. Sem ele, audita o projeto do cwd.
const scanRootIdx = argv.indexOf("--scan-root");
const SCAN_ROOT = scanRootIdx >= 0 ? argv[scanRootIdx + 1] : null;
const CACHE_DIR = path.join(os.homedir(), ".config", "exponencial-agent");
// Cache por host do painel (1 identidade de agente por máquina+plataforma). A ORG
// vem do PRÓPRIO token, não de env — o agente é dono de uma org só.
const CACHE_FILE = path.join(CACHE_DIR, `${BASE.replace(/^https?:\/\//, "").replace(/[^a-z0-9.-]/gi, "_")}.json`);
// Org do agente, resolvida a partir do token (cache ou register). Preenchida em ensureToken().
let AGENT_ORG = null;

const log = (...a) => console.error("[iso-remediacao]", ...a);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function api(method, pathname, { token, body } = {}) {
  const headers = { "content-type": "application/json" };
  if (token) headers.authorization = `Bearer ${token}`;
  const r = await fetch(`${BASE}${pathname}`, { method, headers, body: body ? JSON.stringify(body) : undefined });
  let j = {};
  try { j = await r.json(); } catch {}
  return { status: r.status, body: j };
}

// ---- Auth: device flow / auto-registro + token cache -------------------
// Lê {token, orgId} do cache (ou de EXP_AGENT_TOKEN+EXP_AGENT_ORG).
async function loadCached() {
  if (process.env.EXP_AGENT_TOKEN) {
    return { token: process.env.EXP_AGENT_TOKEN, orgId: process.env.EXP_AGENT_ORG || null };
  }
  try {
    const raw = JSON.parse(await readFile(CACHE_FILE, "utf8"));
    if (raw && raw.token) return { token: raw.token, orgId: raw.orgId || null };
  } catch {}
  return null;
}
async function saveToken(token, orgId) {
  await mkdir(CACHE_DIR, { recursive: true, mode: 0o700 });
  await writeFile(CACHE_FILE, JSON.stringify({ token, orgId, savedAt: new Date().toISOString() }), { mode: 0o600 });
}
// Confirma que o token funciona para a org conhecida (do cache/register). O orgId
// é sempre conhecido no momento em que o token é emitido (register/poll/approve
// retornam orgId), então só precisamos validar, não adivinhar.
async function tokenWorksFor(token, orgId) {
  if (!orgId) return false;
  const r = await api("GET", `/api/admin/orgs/${encodeURIComponent(orgId)}/compliance/overview`, { token });
  return r.status === 200;
}
async function deviceStart() {
  const r = await api("POST", "/api/auth/device/start", { body: { label: `iso-remediacao@${os.hostname()}` } });
  if (r.status !== 200) throw new Error(`device/start falhou: ${r.status} ${JSON.stringify(r.body)}`);
  return r.body; // { device_code, user_code, verification_uri, interval, expires_in }
}
async function devicePoll(deviceCode, intervalSec, expiresInSec) {
  const deadline = Date.now() + (expiresInSec || 900) * 1000;
  let interval = (intervalSec || 5) * 1000;
  while (Date.now() < deadline) {
    const r = await api("POST", "/api/auth/device/poll", { body: { device_code: deviceCode } });
    if (r.status === 200 && r.body.access_token) return { token: r.body.access_token, orgId: r.body.orgId };
    if (r.status === 428) { await sleep(interval); continue; }
    throw new Error(`device/poll erro: ${r.status} ${JSON.stringify(r.body)}`);
  }
  throw new Error("device flow expirou sem aprovação");
}
// Descobre um e-mail para o auto-registro: env EXP_AGENT_EMAIL → git config →
// nome do projeto. Sem e-mail bom, registra anônimo (o backend exige e-mail,
// então caímos num placeholder claramente identificável só se nada melhor existir).
async function discoverEmail() {
  if (process.env.EXP_AGENT_EMAIL) return process.env.EXP_AGENT_EMAIL.trim();
  try {
    const { stdout } = await pexec("git", ["config", "--get", "user.email"], { timeout: 5000 });
    const e = stdout.trim();
    if (e && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e)) return e;
  } catch {}
  return null;
}
function projectHint() {
  try { return path.basename(process.cwd()); } catch { return "trial"; }
}
// Auto-registro de TRIAL (porta sem fricção, default). Cria org nova + capta lead.
async function registerTrial() {
  const email = await discoverEmail();
  if (!email) {
    throw new Error("não encontrei um e-mail (git config user.email vazio). Defina EXP_AGENT_EMAIL=voce@empresa.com ou use --connect para conectar a uma conta existente.");
  }
  log(`auto-registro de avaliação para ${email} (projeto: ${projectHint()})`);
  const r = await api("POST", "/api/auth/agent/register", { body: { email, label: `iso-remediacao@${os.hostname()}`, projectHint: projectHint() } });
  if (r.status !== 200 || !r.body.access_token) throw new Error(`register falhou: ${r.status} ${JSON.stringify(r.body)}`);
  AGENT_ORG = r.body.orgId;
  await saveToken(r.body.access_token, AGENT_ORG);
  log(`organização de avaliação "${AGENT_ORG}" criada (você é owner). Acesse o painel com magic-link usando ${email}.`);
  console.log(JSON.stringify({ event: "registered", orgId: AGENT_ORG, email, role: r.body.role, verification_uri: r.body.verification_uri }));
  return r.body.access_token;
}
// Device flow (cliente existente): só com --connect. Vincula a uma org real,
// aprovado pelo owner no /adm.
async function connectViaDevice() {
  const d = await deviceStart();
  console.error("");
  console.error("  ┌─ APROVAÇÃO NECESSÁRIA ─────────────────────────────");
  console.error(`  │  Acesse: ${d.verification_uri}`);
  console.error(`  │  Código: ${d.user_code}`);
  console.error("  │  (aprove em Organizações → Aprovar agente)");
  console.error("  └────────────────────────────────────────────────────");
  console.log(JSON.stringify({ event: "device_code", device_code: d.device_code, user_code: d.user_code, verification_uri: d.verification_uri }));
  const res = await devicePoll(d.device_code, d.interval, d.expires_in);
  AGENT_ORG = res.orgId;
  await saveToken(res.token, AGENT_ORG);
  log(`token de agente obtido e cacheado (org ${AGENT_ORG})`);
  return res.token;
}
async function ensureToken() {
  const cached = await loadCached();
  if (cached && await tokenWorksFor(cached.token, cached.orgId)) {
    AGENT_ORG = cached.orgId;
    log(`token de agente OK (cache, org ${AGENT_ORG})`);
    return cached.token;
  }
  if (cached) log("token em cache inválido; renovando");
  // --connect = cliente existente (device flow); default = auto-registro de trial.
  return ARGS.has("--connect") ? await connectViaDevice() : await registerTrial();
}

// ---- descoberta do(s) projeto(s) a auditar -----------------------------
// Default: o PROJETO do cwd — sobe até achar o package-lock.json mais próximo.
async function projectFromCwd() {
  let dir = process.cwd();
  for (let i = 0; i < 8; i++) {
    if (existsSync(path.join(dir, "package-lock.json")) && existsSync(path.join(dir, "package.json"))) return dir;
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  // sem lockfile acima: ainda tenta auditar o cwd se houver package.json
  return existsSync(path.join(process.cwd(), "package.json")) ? process.cwd() : null;
}
// Opcional (--scan-root): varre vários projetos sob uma raiz.
async function findProjects(root) {
  const out = [];
  const SKIP = new Set(["node_modules", ".git", "dist", ".cache", "_archive"]);
  async function walk(dir, depth) {
    if (depth > 3) return;
    let entries;
    try { entries = await readdir(dir, { withFileTypes: true }); } catch { return; }
    const hasPkg = entries.some((e) => e.isFile() && e.name === "package.json");
    const hasLock = entries.some((e) => e.isFile() && e.name === "package-lock.json");
    if (hasPkg && hasLock) out.push(dir);
    for (const e of entries) {
      if (e.isDirectory() && !SKIP.has(e.name) && !e.name.startsWith(".")) {
        await walk(path.join(dir, e.name), depth + 1);
      }
    }
  }
  await walk(root, 0);
  return out;
}
async function auditProject(dir) {
  try {
    const { stdout } = await pexec("npm", ["audit", "--json", "--audit-level=low"], { cwd: dir, maxBuffer: 32 * 1024 * 1024, timeout: 120000 });
    return JSON.parse(stdout);
  } catch (err) {
    // npm audit sai com código !=0 quando ACHA vulnerabilidade; o JSON vem no stdout mesmo assim.
    if (err.stdout) { try { return JSON.parse(err.stdout); } catch {} }
    return null;
  }
}
// Todos os pacotes presentes no package-lock.json do projeto (deps + transitivas).
// Usado para limitar a reconciliação: o agente só mexe em riscos de pacotes que
// SÃO dependências deste projeto — nunca fecha risco de outro projeto.
async function installedPackages(dir) {
  const names = new Set();
  try {
    const lock = JSON.parse(await readFile(path.join(dir, "package-lock.json"), "utf8"));
    // lockfile v2/v3: chaves "packages" são caminhos node_modules/<name>
    for (const k of Object.keys(lock.packages || {})) {
      if (!k) continue; // "" = raiz
      const m = k.match(/node_modules\/((?:@[^/]+\/)?[^/]+)$/);
      if (m) names.add(m[1].toLowerCase());
    }
    // lockfile v1: "dependencies" recursivo
    const walkDeps = (deps) => {
      for (const [n, v] of Object.entries(deps || {})) {
        names.add(n.toLowerCase());
        if (v && v.dependencies) walkDeps(v.dependencies);
      }
    };
    walkDeps(lock.dependencies);
  } catch {}
  return names;
}
// Extrai { pkgName -> maxSeverity } do JSON do npm audit (v2/v7+).
function vulnsFromAudit(audit) {
  const map = new Map();
  if (!audit) return map;
  const vulns = audit.vulnerabilities || {};
  for (const [name, v] of Object.entries(vulns)) {
    const sev = v.severity || "low";
    map.set(name.toLowerCase(), sev);
  }
  return map;
}
const SEV_RANK = { info: 0, low: 1, moderate: 2, high: 3, critical: 4 };

// Normaliza o "asset" de um risco para o(s) nome(s) de pacote.
function pkgNamesFromAsset(asset) {
  return String(asset || "")
    .split(",")
    .map((s) => s.trim()
      .replace(/^npm:/, "")
      .replace(/@[0-9].*$/, "")   // basic-ftp@5.0.5 → basic-ftp
      .replace(/\s+[0-9].*$/, "") // basic-ftp 5.0.5 → basic-ftp
      .trim().toLowerCase())
    .filter(Boolean);
}

async function main() {
  log(`base=${BASE}${SCAN_ROOT ? ` scanRoot=${SCAN_ROOT}` : ` projeto=${process.cwd()}`}${DRY ? " (DRY-RUN)" : ""}`);
  const token = await ensureToken();          // resolve/registra o token e preenche AGENT_ORG
  log(`org do agente: ${AGENT_ORG}`);
  if (ARGS.has("--auth-only")) { log("auth-only: pronto."); return; }

  // 1) descobrir projeto(s): default = projeto do cwd; --scan-root = multi-projeto
  let projects;
  if (SCAN_ROOT) {
    projects = await findProjects(SCAN_ROOT);
  } else {
    const p = await projectFromCwd();
    if (!p) throw new Error(`nenhum package.json encontrado a partir de ${process.cwd()} (rode dentro do projeto, ou use --scan-root <dir>)`);
    projects = [p];
  }
  log(`projeto(s) a auditar: ${projects.length}${SCAN_ROOT ? "" : ` → ${projects[0]}`}`);
  const vulnAll = new Map();      // pkg -> maxSeverity (vulnerável AGORA)
  const installedAll = new Set(); // todo pacote que é dependência dos projetos auditados
  let auditedOk = 0;
  for (const dir of projects) {
    const audit = await auditProject(dir);
    if (audit) auditedOk++;
    for (const [pkg, sev] of vulnsFromAudit(audit)) {
      const prev = vulnAll.get(pkg);
      if (!prev || SEV_RANK[sev] > SEV_RANK[prev]) vulnAll.set(pkg, sev);
    }
    for (const n of await installedPackages(dir)) installedAll.add(n);
  }
  log(`auditados ${auditedOk}/${projects.length}; pacotes do projeto: ${installedAll.size}; vulneráveis agora: ${vulnAll.size}`);

  // 2) riscos abertos de dependência no /adm
  const rRisks = await api("GET", `/api/admin/orgs/${encodeURIComponent(AGENT_ORG)}/compliance/risks`, { token });
  if (rRisks.status !== 200) throw new Error(`GET risks falhou: ${rRisks.status}`);
  const risks = rRisks.body.risks || [];
  const depRisks = risks.filter((r) => r.status === "open" && pkgNamesFromAsset(r.asset).length);

  const plan = { close: [], keepPending: [], openNew: [] };

  // 2a) reconciliar riscos abertos — SÓ os cujo pacote é dependência DESTE
  //     projeto (senão é risco de outro projeto: o agente não toca).
  let skippedForeign = 0;
  for (const risk of depRisks) {
    const names = pkgNamesFromAsset(risk.asset);
    const ownsAny = names.some((n) => installedAll.has(n));
    if (!ownsAny) { skippedForeign++; continue; } // pacote não pertence a este projeto
    const stillVuln = names.find((n) => vulnAll.has(n));
    if (stillVuln) {
      plan.keepPending.push({ id: risk.id, asset: risk.asset, pkg: stillVuln, severity: vulnAll.get(stillVuln) });
    } else {
      // pacote É dep deste projeto e NÃO está mais vulnerável → resolvido
      plan.close.push({ id: risk.id, asset: risk.asset, names: names.filter((n) => installedAll.has(n)) });
    }
  }
  if (skippedForeign) log(`ignorados ${skippedForeign} risco(s) de pacote que não é dependência deste projeto`);

  // 2b) high/critical no audit sem risco aberto correspondente → abrir
  const knownPkgs = new Set(depRisks.flatMap((r) => pkgNamesFromAsset(r.asset)));
  for (const [pkg, sev] of vulnAll) {
    if ((sev === "high" || sev === "critical") && !knownPkgs.has(pkg)) {
      plan.openNew.push({ pkg, severity: sev });
    }
  }

  const lowMod = [...vulnAll.entries()].filter(([, s]) => s === "low" || s === "moderate");
  const today = new Date().toISOString().slice(0, 10);

  log(`plano: fechar ${plan.close.length} · pendentes ${plan.keepPending.length} · abrir ${plan.openNew.length} · low/mod p/ evidência ${lowMod.length}`);
  if (DRY) {
    console.log(JSON.stringify({ event: "plan", dryRun: true, ...plan, lowModerate: lowMod.length }, null, 2));
    return;
  }

  // 3) aplicar no /adm
  let closed = 0, pended = 0, opened = 0;
  for (const c of plan.close) {
    const note = `Remediado: npm audit sem vulnerabilidade para ${c.names.join("/")} em ${today}. Fechado automaticamente pelo agente de remediação (A.8.8).`;
    const r = await api("PATCH", `/api/admin/orgs/${encodeURIComponent(AGENT_ORG)}/compliance/risks/${encodeURIComponent(c.id)}`, {
      token, body: { status: "closed", notes: note },
    });
    if (r.status === 200) { closed++; log(`fechado: ${c.asset}`); }
    else log(`WARN não fechou ${c.asset}: ${r.status} ${JSON.stringify(r.body)}`);
  }
  for (const p of plan.openNew) {
    const r = await api("POST", `/api/admin/orgs/${encodeURIComponent(AGENT_ORG)}/compliance/risks`, {
      token, body: {
        asset: `npm:${p.pkg}`, threat: `Vulnerabilidade técnica em dependência npm: ${p.pkg} (severidade ${p.severity}). Detectado por npm audit.`,
        likelihood: p.severity === "critical" ? 5 : 4, impact: p.severity === "critical" ? 5 : 4,
        treatment: "mitigate", controlRefs: ["A.8.8"], notes: `Aberto automaticamente pelo agente (A.8.8) em ${today} via npm audit.`,
      },
    });
    if (r.status === 200) { opened++; log(`aberto: ${p.pkg} (${p.severity})`); }
    else log(`WARN não abriu ${p.pkg}: ${r.status}`);
  }
  // nota de pendência (1 evento agregado) para os que persistem
  if (plan.keepPending.length) {
    const lines = plan.keepPending.map((k) => `- ${k.asset} (${k.pkg}: ${k.severity})`).join("\n");
    await api("POST", `/api/admin/orgs/${encodeURIComponent(AGENT_ORG)}/compliance/events`, {
      token, body: { type: "note", title: `Vulnerabilidades ainda pendentes (${plan.keepPending.length}) — A.8.8`, date: today,
        summary: `O agente verificou via npm audit e estas dependências continuam vulneráveis (risco mantido aberto):\n${lines}` },
    });
    pended = plan.keepPending.length;
  }
  // snapshot da rodada
  await api("POST", `/api/admin/orgs/${encodeURIComponent(AGENT_ORG)}/compliance/events`, {
    token, body: { type: "evidence-snapshot", title: `npm audit — rodada do agente (A.8.8)`, date: today,
      summary: `Varredura npm audit em ${auditedOk} projeto(s). Pacotes vulneráveis: ${vulnAll.size} (low/moderate: ${lowMod.length}). Ações: ${closed} risco(s) fechado(s), ${opened} aberto(s), ${pended} pendente(s).`,
      data: { auditedProjects: auditedOk, vulnPackages: vulnAll.size, closed, opened, pending: pended } },
  });

  log(`FEITO: ${closed} fechados, ${opened} abertos, ${pended} pendentes, snapshot gravado.`);
  console.log(JSON.stringify({ event: "done", closed, opened, pending: pended, vulnPackages: vulnAll.size }));
}

main().catch((err) => { log("ERRO:", err.message); process.exit(1); });
