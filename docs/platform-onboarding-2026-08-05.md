# Platform onboarding audit — 2026-08-05

Every URL supplied for this onboarding round was opened and classified before
the ingestion registry changed. A source is enabled only when it exposes a
public catalog or repository containing real `SKILL.md` trees and the worker can
acquire it without executing publisher-controlled code.

| Supplied URL | Decision | Registry mapping | Evidence |
| --- | --- | --- | --- |
| `https://useai.live/hermes/` | Not enabled | Audit only | Installer/localization page; its linked localization repository contained zero `SKILL.md` files. |
| `https://hermes-agent.org/` | Canonicalized | `hermes-agent` | Product site links `NousResearch/hermes-agent`; that repository contained 183 `SKILL.md` trees. |
| `https://hermesagents.net/zh/` | Not enabled | Audit only | Documentation/product site with no independent skill catalog. |
| `https://skillsllm.com/` | Enabled | `skillsllm` | Declared public sitemap and detail pages with GitHub repository handoffs. |
| `https://hermesagentai.cn/` | Canonicalized | `hermes-agent` | Product site links the same canonical repository. The repeated supplied URL was deduplicated. |
| `https://www.hermes-ai-cn.com/` | Canonicalized | `hermes-agent` | Product site links the same canonical repository. |
| `https://hermes-agent.org.cn/` | Canonicalized | `hermes-agent` | Product site links the same canonical repository and the Agent Skills specification. |
| `https://hermes-ai-cn.com/` | Canonicalized | `hermes-agent` | Redirects to the `www` host above. |
| `https://skills.sh/` | Enabled | `skills-sh` | Declared skill-only sitemap shards and GitHub repository handoffs. |
| `https://agent-skill.co/` | Not enabled | Audit only | Directory cards point to an awesome-list repository containing no local `SKILL.md` trees. The repeated supplied URL was deduplicated. |
| `https://agentskills.io/` | Not enabled | Audit only | Specification/documentation site rather than a skill-sharing catalog. The repeated supplied URL was deduplicated. |
| `https://awesomeagent.ai/` | Not enabled | Audit only | DNS did not resolve during the audit. |
| `https://skillregistry.io/` | Enabled | `skillregistry` | Declared public sitemap and same-origin Markdown skill downloads. |
| `https://mcpservers.org/agent-skills` | Enabled | `mcpservers-agent-skills` | Declared skill-only sitemap and GitHub tree handoffs. |
| `https://smithery.ai/` | Enabled | `smithery-skills` | Declared skill sitemap shards and GitHub repository handoffs. |
| `https://lobehub.com/skills` | Enabled | `lobehub-skills` | Declared agent feed links public skill details with GitHub tree handoffs. |
| `https://mcpmarket.com/tools/skills` | Not enabled | Audit only | Catalog is visible to humans, but identified acquisition requests returned HTTP 429 and no declared public crawl surface was available. |
| `https://aiagentsdirectory.com/` | Enabled | `ai-agents-directory` | Declared skill-only sitemap and GitHub tree handoffs. |

The sitemap catalog adapter rejects cross-origin catalog redirects, follows
only platform-specific skill sitemap shards, limits response sizes and request
counts, rate-limits every request, accepts same-origin `SKILL.md` downloads,
and otherwise hands off only to public `https://github.com/<owner>/<repo>`
sources. Acquired files remain data and are never executed during ingestion.
