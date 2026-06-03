# @exponencial/iso-remediacao

**Conformidade ISO/IEC 27001 que se mantém viva — operada pelo seu agente de IA.**

Um comando e o seu agente passa a verificar as vulnerabilidades técnicas do seu
projeto (`npm audit`) e a alimentar a sua conformidade **ISO/IEC 27001** na
plataforma da [Exponencial](https://exponencialadm.net) — abrindo, fechando e
**evidenciando** riscos automaticamente, com trilha de auditoria datada.

Sem cadastro e sem fricção: na primeira execução o agente cria a **sua
organização de avaliação** e já começa a trabalhar.

> Este é o controle **A.8.8 — Gestão de vulnerabilidades técnicas** do Anexo A da
> ISO/IEC 27001:2022, funcionando de verdade: detecção → tratamento → evidência,
> em vez de uma política parada no papel.

Também é uma porta de entrada para uma dor maior de segurança: **governança de
agentes de IA, skills, extensões VS Code, MCPs e shadow AI**. Se um agente pode
ler código, executar comandos ou chamar APIs, ele precisa entrar no inventário,
na revisão de privilégio e na trilha de evidências da empresa.

---

## Instalação e uso

Dentro do diretório do seu projeto (que tem `package.json` + `package-lock.json`):

```bash
# executa direto, sem instalar (recomendado)
npx @exponencial/iso-remediacao
```

Ou instale globalmente:

```bash
npm install -g @exponencial/iso-remediacao
iso-remediacao
```

### O que acontece na primeira vez

1. O agente identifica o seu e-mail (de `git config user.email`, ou defina
   `EXP_AGENT_EMAIL`) e **cria uma organização de avaliação** isolada, com você
   como proprietário.
2. Roda `npm audit` no projeto e **sincroniza** com a sua conformidade:
   - vulnerabilidade **resolvida** → fecha o risco com evidência datada;
   - vulnerabilidade **persistente** → registra a pendência (mantém o risco aberto);
   - **alta/crítica** nova → abre um risco no controle A.8.8;
   - baixas/moderadas → entram como evidência do ciclo.
3. Você acompanha tudo no painel: acesse
   [exponencialadm.net/adm](https://exponencialadm.net/adm/) e entre com o **mesmo
   e-mail** (link mágico, sem senha).

### Já é cliente?

Conecte o agente à sua conta existente em vez de criar uma avaliação:

```bash
npx @exponencial/iso-remediacao --connect
```

Um proprietário da organização aprova o agente no painel
(**Organizações → Aprovar agente**), colando o código exibido. Depois disso, as
execuções são automáticas.

---

## Comandos

| Comando | O que faz |
|---|---|
| `npx @exponencial/iso-remediacao` | Avaliação sem fricção: registra (se preciso), audita o projeto e sincroniza |
| `… --dry-run` | Mostra o plano (o que fecharia/abriria), **sem** escrever no painel |
| `… --connect` | Conecta a uma conta existente (aprovação do proprietário) |
| `… --auth-only` | Apenas garante a credencial do agente |
| `… --scan-root <dir>` | Varre vários projetos sob um diretório |
| `… --help` | Mostra ajuda e não executa auditoria |

## Por que isso importa para segurança de agentes

Empresas estão adotando Claude Code, Cursor, OpenClaw e agentes similares antes
de terem inventário e política claros. O resultado é uma pergunta difícil para
TI, segurança e compliance:

> Que agente está rodando, com quais skills, extensões e privilégios?

Esta primeira skill resolve um caso bem delimitado:

- roda dentro de um projeto npm;
- usa escopo mínimo;
- não altera dependências;
- transforma uma verificação técnica em evidência ISO 27001 A.8.8.

A mesma arquitetura pode evoluir para inventário de agentes, skills, MCPs e
extensões VS Code, sempre separando descoberta, risco, aprovação e evidência.

### Variáveis de ambiente

| Variável | Padrão | Para quê |
|---|---|---|
| `EXP_AGENT_EMAIL` | `git config user.email` | E-mail dono da organização de avaliação |
| `EXP_ADMIN_BASE` | `https://exponencialadm.net` | Endpoint da plataforma |
| `EXP_AGENT_TOKEN` | — | Injeta uma credencial existente (CI) |

---

## Segurança

- **Credencial de agente com escopo mínimo.** O token só envia evidências de
  conformidade para a **sua** organização — nunca é administrador e nunca alcança
  dados de outra organização.
- **Isolamento por cliente.** Cada organização tem seu espaço; toda requisição é
  reautorizada no servidor.
- **Sem segredos no código.** A credencial fica em
  `~/.config/exponencial-agent/` (modo `600`); apenas o hash é guardado no servidor.
- **Só leitura local.** O agente roda `npm audit` (não altera seu código nem suas
  dependências); ele apenas **relata** o resultado para a conformidade.

---

## Sobre

Mantido pela **Exponencial Administração & Tecnologia** — consultoria em gestão e
tecnologia, certificada **ISO 9001, ISO 14001 e ISO 27001**.

- Plataforma: <https://exponencialadm.net/pt-br/conformidade/>
- Como instalar nos seus agentes: <https://exponencialadm.net/pt-br/instalar-agente/>
- ISO 27001 A.8.8 + npm audit: <https://exponencialadm.net/pt-br/iso-27001-a-8-8-npm-audit/>
- Governança de agentes de IA: <https://exponencialadm.net/pt-br/governanca-agentes-ia/>
- Inventário de agentes, skills e extensões: <https://exponencialadm.net/pt-br/inventario-agentes-ia-skills-extensoes/>
- Licença: [MIT](./LICENSE)
