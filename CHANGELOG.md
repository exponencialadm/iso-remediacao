# Changelog

## 1.0.0 — 2026-06-01

Primeira versão pública estável do **agente de remediação ISO/IEC 27001** (controle
A.8.8 — gestão de vulnerabilidades técnicas).

- Roda `npm audit` no projeto do cliente e reconcilia a conformidade na plataforma
  Exponencial: **abre, fecha e evidencia** vulnerabilidades automaticamente.
- Atua **apenas** sobre pacotes que são dependência do projeto auditado.
- Autenticação por **token de agente** escopado a uma organização (nunca super-admin);
  auto-registro de avaliação sem fricção ou conexão a conta existente via device flow.
- **Sem dependências de terceiros** em runtime e **sem scripts de ciclo de vida**.
- Publicado via **npm Trusted Publishing (OIDC)** com **provenance** assinada.
