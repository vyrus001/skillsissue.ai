# Third-party material

## SkillJect

`SkillJect/` is a Git submodule pinned to upstream commit
`6598997b76044fa00abe0a4416064fbd2eab33ff` from
<https://github.com/jiaxiaojunQAQ/SkillJect>.

At the pinned revision, the upstream repository does not contain a repository-
level license or SPDX declaration. Its presence here is a reference to an
upstream Git object, not a relicensing or vendoring of its contents. Do not
modify, redistribute, or incorporate its code into another artifact without
obtaining permission from its authors. Individual sample directories may carry
their own licenses.

SkillJect includes intentionally hostile fixtures. Treat every sample and script
as untrusted and execute them only inside the detonation target.

## Agent CLIs

The sandbox image installs integrity-locked npm artifacts for
`@openai/codex` 0.141.0 and `@anthropic-ai/claude-code` 2.1.202. Codex declares
Apache-2.0; Claude Code carries Anthropic's license referenced by its package.
These tools and their licenses remain third-party material and are not
relicensed by this repository's first-party project license. Version and
integrity pins are recorded in `containers/agent-clis/package-lock.json`.

## Acquired skills and platform metadata

The repository's first-party project license does not relicense SkillJect,
downloaded skills, their manifests, or their bundled contents. Skill authors
and hosting platforms retain their applicable rights. Before redistributing or
retaining an acquired corpus, review each artifact's license and the source
platform's current terms.

`data/platforms.csv` seeds ClawHub using its public API documentation and
acceptable-use URL. Those external documents may change. A platform candidate
discovered from telemetry is evidence only; it remains disabled until an
operator verifies the site, its ownership, terms, rate limits, and acquisition
method.
