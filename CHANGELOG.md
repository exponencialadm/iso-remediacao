# Changelog

## 0.1.1 — 2026-06-01

- Publicação migrada para **npm Trusted Publishing (OIDC)** via GitHub Actions:
  sem token de longa duração, com **provenance** assinada (origem verificável na
  página do pacote no npm). Sem mudanças no comportamento do agente.

## 0.1.0 — 2026-06-01

- Primeira versão pública: agente de remediação **ISO/IEC 27001** (controle
  A.8.8 — gestão de vulnerabilidades técnicas). Roda `npm audit` no projeto do
  cliente e reconcilia automaticamente (abre/fecha/evidencia) a conformidade na
  plataforma Exponencial.
