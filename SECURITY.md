# Política de Segurança / Security Policy

> Exponencial Administração & Tecnologia — `@exponencial/iso-remediacao`

## Reportar uma vulnerabilidade

Se você encontrar uma falha de segurança neste pacote, **não abra uma issue
pública**. Reporte de forma responsável (coordinated disclosure):

- E-mail: **cto@exponencialadm.net**
- Ou abra um aviso privado em **GitHub Security Advisories**
  (aba *Security* → *Report a vulnerability*).

Inclua, se possível: versão afetada, passos de reprodução, impacto e qualquer
prova de conceito. Confirmamos o recebimento em até **5 dias úteis** e
trabalhamos uma correção coordenada antes de qualquer divulgação pública.

To report a security issue, email **cto@exponencialadm.net** or use GitHub
Security Advisories. Please do not open public issues for vulnerabilities.

## Versões suportadas

| Versão | Suportada |
|--------|-----------|
| 0.x    | ✅ (linha atual) |

## Como o pacote trata segurança (postura)

Este agente roda **dentro do projeto do cliente** e fala com a plataforma
`exponencialadm.net`. Invariantes de segurança (não relaxar):

- **Sem dependências de terceiros** em runtime — só APIs nativas do Node. Nada
  de cadeia transitiva a comprometer.
- **Sem scripts de ciclo de vida** (`postinstall` etc.) — `npx` não executa
  código arbitrário na instalação.
- **Comandos externos via `execFile`** (nunca shell) — sem injeção de comando.
- **Token de agente** guardado só em `~/.config/exponencial-agent/` com permissão
  `0600`; **nunca** é impresso em log nem versionado.
- **Telemetria mínima**: o agente envia apenas nomes de pacotes e severidades do
  `npm audit` (evidência de conformidade) — **nunca** código-fonte, segredos ou
  variáveis de ambiente.
- **Publicação via OIDC Trusted Publishing** (sem token de longa duração) com
  **provenance** assinada — veja a procedência na página do pacote no npm.
