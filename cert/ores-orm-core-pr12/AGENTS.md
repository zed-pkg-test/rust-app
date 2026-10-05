# ores-orm-core agent notes

This repository implements ORM-first derivative schema/type/validator tooling.

- Durable codegen, checks, validators and repository scripts are Rust-first; do not add Python tooling.
- Human-authored TypeSpec and JSON Schema Draft 2020-12 remain independent peer authorities. ORM-derived artifacts are evidence, never a third authored authority.
- Parse Diesel and SeaORM independently. Do not resolve a mismatch by choosing one ORM as canonical.
- Public projections must be explicit allowlists and must be admitted against retained TJSV Contract IR evidence before publication.
- Preserve database/wire names exactly. Escaping a language reserved word must not change the serialized name.
- Fail closed on unsupported or ambiguous ORM constructs; do not silently widen validators.
- Generated output belongs under `generated/` and must carry reproducible provenance.

For fleet-wide guidance also follow `ORESoftware/my-ai` `AGENTS.md` and `SHARED.md`.
