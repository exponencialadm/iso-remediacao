---
name: iso-remediacao
description: "Agente de remediação ISO 27001 A.8.8 — roda npm audit no projeto atual, fecha vulnerabilidades resolvidas e registra pendências/evidências no painel de conformidade da Exponencial. Use quando o usuário pedir para verificar/remediar vulnerabilidades de dependências, rodar o loop de gestão de vulnerabilidades técnicas (A.8.8), ou sincronizar o npm audit com a conformidade ISO."
---

# iso-remediacao — Gestão de vulnerabilidades técnicas (ISO 27001 A.8.8)

Agente que fecha o loop do controle **A.8.8 (Gestão de vulnerabilidades técnicas)**
da ISO/IEC 27001:2022 para a plataforma da Exponencial. Roda **dentro do projeto
do cliente** (o diretório atual, que já tem `package.json`), confere as
vulnerabilidades com `npm audit` e reconcilia com o registro de riscos da
organização no `/adm`.

## O que faz (loop A.8.8)

1. **Autentica sem fricção (default):** se não há token, faz **auto-registro de
   avaliação** — cria uma organização nova e isolada com o seu e-mail (de
   `git config user.email` ou `EXP_AGENT_EMAIL`) como owner e já começa a
   trabalhar. Depois você entra no painel via **magic-link** com esse e-mail.
   Para conectar a uma **conta existente**, use `--connect` (device flow,
   aprovado pelo owner no `/adm`). Token cacheado em
   `~/.config/exponencial-agent/<org>.json` (execuções seguintes rodam sozinhas).
2. Roda `npm audit --json` no projeto atual.
3. Reconcilia com os riscos de dependência **abertos** da org:
   - pacote **saiu** do audit → **resolvido** → fecha o risco com evidência
     datada (autoria do agente);
   - pacote **continua** vulnerável → registra **nota de pendência** (mantém aberto);
   - vuln **high/critical** sem risco aberto → **abre** risco (source=auto, A.8.8);
   - low/moderate → entram no **evidence-snapshot** da rodada.
4. Grava 1 **evidence-snapshot** por rodada no controle A.8.8.

## Como executar

O trabalho é determinístico — está no script. **Rode dentro do projeto do cliente:**

```bash
# avaliação sem fricção: auto-registra (se preciso) + audita o projeto + reconcilia
node <skill-dir>/remediate.mjs

# só checar o plano sem escrever no /adm
node <skill-dir>/remediate.mjs --dry-run

# conectar a uma conta JÁ existente (device flow, aprovado pelo owner)
node <skill-dir>/remediate.mjs --connect

# só garantir o token
node <skill-dir>/remediate.mjs --auth-only
```

`<skill-dir>` é o diretório desta skill (onde está `remediate.mjs`).

### Primeira vez

- **Avaliação (default):** o script cria uma **organização nova** com o seu
  e-mail (de `git config user.email`, ou defina `EXP_AGENT_EMAIL`) e já roda.
  Para ver o resultado no painel, faça login em `https://exponencialadm.net/adm/`
  com **magic-link** usando esse mesmo e-mail.
- **Conta existente (`--connect`):** o script imprime um **código** + **URL**;
  o owner aprova em **`/adm` → Organizações → Aprovar agente**. Depois o token
  fica cacheado e as execuções seguintes são não-interativas.

Em **stdout** o script emite linhas JSON estruturadas (`{"event":"registered",…}`,
`{"event":"device_code",…}`, `{"event":"done",…}`) para orquestração; logs
humanos vão para stderr.

## Variáveis de ambiente

- `EXP_AGENT_ORG` — org-alvo (default `exponencial`; normalmente já vem do token).
- `EXP_ADMIN_BASE` — base da API (default `https://exponencialadm.net`).
- `EXP_AGENT_TOKEN` — injeta um token de agente e pula o device flow (útil em CI/teste).
- `--scan-root <dir>` — modo multi-projeto (varre vários projetos sob `<dir>`);
  sem ele, audita o projeto do diretório atual.

## Invariantes de segurança

- O token de agente **nunca** é super-admin; só faz `compliance:write` na **org
  aprovada** (cross-org → 403; Sec-AI → 403).
- O token nunca é impresso; só seu hash é persistido no servidor.
- Riscos de origem `secai`/`auto` são append-only: o agente **fecha** (com
  justificativa) ou **mantém** — nunca apaga.
