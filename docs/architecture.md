# Architecture

## The two directions are complementary

There are two different derivation directions in the fleet and they must not be collapsed into one source-of-truth story.

### Contract-first

`*-interfaces` owns independently authored TypeSpec and JSON Schema. TJSV proves semantic convergence. `ores-contracts` can then project persistence/codegen evidence such as SQL, Diesel, SeaORM and language types.

### ORM-first

`*-orm-core` contains executable/private ORM definitions. `ores-orm-core` independently normalizes Diesel and SeaORM into `ores.orm-core.ir/v1`, requires the common structural semantics to converge, then emits derivative candidates such as strict JSON Schema and language validators.

The ORM-first lane is useful for the same reason `drizzle-zod` is useful: database model changes can mechanically produce matching data-shape validators and DTOs. The difference is that an ORESoftware public artifact has an additional admission boundary.

## Public vs private output

Private/server-only derivatives may be produced from converged ORM evidence alone. Public derivatives are candidates until they have been checked against the exact TJSV Contract IR and retained parity receipt for the owning `*-interfaces` contract.

This prevents a private database column from becoming public by accident and prevents an ORM's weaker type system from erasing business constraints such as patterns, min/max lengths, enum membership, tagged unions, or semantic formats.

A public-admission lane should compare the ORM-derived Draft 2020-12 schema to the mapped Contract IR assertion schema. Where the contract is stricter than ORM evidence, the public runtime validator must retain the contract constraint; the ORM lane may never weaken it.

## Diesel and SeaORM are peer witnesses

Neither ORM wins. The initial structural comparison covers the common subset both lanes can prove reliably: schema/table name, column/storage name, scalar/array/named logical type, nullability and primary-key membership.

Defaults, generated expressions, checks, indexes, RLS, grants, extensions and vector dimensions are not guessed from ORM source. Use explicit `.ores-orm.toml` policy and/or database-catalog evidence, and retain the evidence source in receipts.

## Shape algebra

Presence and nullability are independent axes. For a create field, a non-null field without a default is required; a nullable field may be omitted and may explicitly be null; a defaulted field may be omitted without becoming nullable.

For a row/read shape every selected property is required, even when its value is nullable. This matters in Rust because plain `Option<T>` often conflates a missing field with a present JSON `null`. Rust DTO generation therefore needs presence-aware helper wrappers or mandatory schema validation before deserialization.

`update` is replacement-style for writable fields. `patch` is partial. Generated fields are excluded. Immutable fields may be accepted on create when explicitly exposed but are excluded from subsequent writes.

## Explicit exposure

The generator does not infer exposure from field names. Public projections are allowlists in policy/contract mapping. An empty allowlist means nothing is public.

## Naming

Database/wire names are preserved exactly by default. Language identifiers may be escaped for reserved words, but serialization must keep the original name. The current fleet preference is snake_case; automatic camelCase conversion from older experiments is not inherited here.

## Language adapters

The normalized shape IR is the shared semantic input. Adapters must have golden positive/negative fixtures and prove equivalent acceptance/rejection behavior.

- Rust: Serde DTOs plus strict presence/null handling; Schemars may emit a comparison witness but is not authority.
- TypeScript: Zod schemas/types or a pinned equivalent runtime validator, checked against the canonical Draft 2020-12 derivative schema.
- Dart: generated models plus explicit key-presence/type/format validation.
- Gleam: generated types and `gleam/dynamic` decoders with equivalent missing/null behavior.
- WIT: downstream ABI/interface compatibility evidence through `ores-wit`; WIT does not replace JSON validation constraints.

Public language emission must bind to admitted contract evidence so DB-only semantics cannot silently redefine the wire contract.
