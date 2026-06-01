#!/usr/bin/env node
// Entrypoint para `npx @exponencial/iso-remediacao`.
// Apenas carrega o agente de remediação (remediate.mjs faz todo o trabalho:
// auto-registro/--connect, npm audit do projeto atual e reconciliação A.8.8).
import { fileURLToPath } from "node:url";
import path from "node:path";

const here = path.dirname(fileURLToPath(import.meta.url));
await import(path.join(here, "..", "remediate.mjs"));
