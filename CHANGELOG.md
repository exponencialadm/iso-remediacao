# Changelog

## 1.0.2 — 2026-06-03

Republicação de descoberta e documentação:

- Corrige a publicação com `README.md` no pacote npm.
- Amplia descrição e palavras-chave para `grc`, `ai-compliance`,
  `agent-governance`, `ai-agent-security`, `iso42001`, `skills` e
  `vscode-extensions`.
- Explicita a relação entre o agente A.8.8 e a governança empresarial de agentes
  de IA, skills, MCPs e extensões.
- Aponta a homepage para a landing específica de ISO 27001 A.8.8 + `npm audit`.
- Trata `--help`/`-h` como comando passivo, sem executar auditoria nem escrever
  evidências no painel.

## 1.0.1 — 2026-06-01

Republicação técnica, **sem mudança de código ou comportamento** em relação à 1.0.0.
Reemite a *provenance* (OIDC Trusted Publishing) vinculada ao commit de origem atual.

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
