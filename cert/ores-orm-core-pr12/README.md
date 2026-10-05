# ores-orm-core

ORM-first derivative schema and validator tooling for the ORESoftware fleet.

This repository fills the inverse/code-first lane that is intentionally different from `ORESoftware/ores-contracts`:

```text
Diesel schema/model definitions -----> ORM IR_D --\
                                                  +--> parity gate --> converged derivative ORM IR
SeaORM entity/model definitions -----> ORM IR_S --/                     |
                                                                         +--> exact policy-derived shapes
                                                                         +--> Rust Serde types
                                                                         +--> JSON Schema 2020-12
                                                                         +--> TypeScript validators/types
                                                                         +--> Dart validators/types
                                                                         +--> Gleam decoders/types
                                                                         |
                                                                         +--> TJSV admission before public promotion
                                                                         |
                                                                         +--> optional WIT/binding evidence downstream
```

It is analogous in purpose to deriving Zod schemas from Drizzle tables, but it is deliberately stricter about provenance and authority.

## Authority boundary

Human-authored TypeSpec and human-authored JSON Schema Draft 2020-12 remain independent peer authorities in `*-interfaces` repositories. `ORESoftware/typespec-json-schema-validator` (TJSV) owns their generic semantic parity and Contract IR admission. `ORESoftware/ores-contracts` owns contract-first persistence/codegen convergence for contract families that declare persistence semantics. `ORESoftware/ores-wit` owns WIT validation/canonicalization/binding orchestration.

`ores-orm-core` does **not** promote Diesel, SeaORM, Serde, generated JSON Schema, or a database catalog into a third authored authority. ORM-first output is derivative evidence. Public output may be published only when it is compatible with the exact admitted public contract surface and its retained Contract IR/receipts.

Binding Contract IR and receipt bytes into a derivative manifest is provenance only. It does **not** certify admission. The generator always marks a public derivative as `blocked_pending_contract_admission`; a separate TJSV verification step owns the promotion decision.

## Inputs

The first-class input lanes are independent and must converge when both are configured:

- Diesel `table!` schema output, normally produced by `diesel print-schema`, plus explicitly declared model metadata where needed.
- SeaORM entity/model definitions, including SeaORM 2 dense entities and generated entities from `sea-orm-cli generate entity`.
- Optional database catalog evidence for DB-first verification. Catalog evidence strengthens the proof but does not silently override either ORM lane.

A single ORM lane may be used during bootstrap, but release/publication policy can require both lanes. Unsupported or ambiguous ORM constructs fail closed rather than being guessed.

## Derived shape families

Generation is shape-aware rather than emitting one struct for every purpose:

- `row` / `select`: database-readable representation; every selected column is present even when its value is SQL `NULL`.
- `create` / `insert`: client-settable create fields; generated/default-only/immutable fields are excluded unless explicitly allowed.
- `update`: replace/update shape with field mutability policy applied.
- `patch`: partial update shape; all writable fields optional and the object itself must contain at least one field.
- `public_read`: explicitly public projection of a row.
- `public_create`, `public_update`, and `public_patch`: explicitly public write projections.

Presence and nullability are separate dimensions. The emitters preserve required/non-null, required/nullable, optional/non-null, and optional/nullable semantics rather than treating `NULL` as “missing.”

Public/private membership is explicit configuration/metadata. The generator must never decide that a field is secret or public from a name such as `password`, `token`, `_hidden`, or `internal`.

## Exact lineage

A derivative bundle is emitted only when all of these agree in one call:

1. the supplied converged ORM IR validates;
2. the supplied policy validates against that entire IR, including stale/orphan table entries;
3. the evidence's ORM-IR digest matches the exact supplied IR bytes;
4. the supplied shape is re-derived from that exact IR + policy + `ShapeKind`; and
5. the re-derived shape is byte-for-byte semantically equal to the supplied shape.

This prevents a hand-constructed or stale shape from inheriting provenance from an unrelated ORM snapshot. Artifact paths, type names, source identifiers, shape bytes, source inputs, generator options, and generated files all receive deterministic identities/digests.

## Naming

Wire and database names are preserved exactly. Generated language identifiers may escape reserved words, but escaping must not alter the serialized name. Fleet defaults prefer `snake_case`; this repository does not inherit older generators' automatic camelCase conversion. Any name transformation must be explicit, deterministic, and represented in provenance.

Quoted database identifiers may contain punctuation or path-like characters, so generated artifact paths never interpolate raw table identities. Paths use deterministic collision-free encodings. Generated language identifiers use reversible escaping and fail before emission if a target-specific collision remains.

## Validation targets

The canonical derivative validation artifact is Draft 2020-12 JSON Schema plus a normalized ORM IR. Language packages consume the same admitted semantics:

- Rust: strict `serde` DTOs with unknown-field rejection and explicit presence/nullability deserializers. The sibling Draft 2020-12 JSON Schema is canonical; the generated DTO intentionally does not infer a weaker schema from `Option<T>`.
- TypeScript: generated types plus strict Zod runtime schemas.
- Dart: generated typed models plus presence-aware runtime validation.
- Gleam: generated record/custom types plus `gleam/dynamic` decoders/validators.

The CI runtime witness compiles/type-checks the emitted Rust, TypeScript/Zod, Dart, and Gleam sources instead of treating source-string assertions as sufficient evidence.

Cross-runtime domains fail closed when an ORM type does not by itself determine one portable wire representation. This currently includes unrestricted `int64`, `float32`, decimal, UUID, calendar date, date-time, bytes, and unresolved named database types. They require a reviewed admitted mapping before public emission. The deliberately small portable subset currently emitted without extra mapping evidence is Boolean, Int16, Int32, Float64, String, and generic JSON.

Additional language adapters can be added without changing the ORM IR or authority model.

## Relationship to product repositories

Typical flow:

```text
<product>-interfaces                 authored TypeSpec + authored JSON Schema
        |                                      |
        +-------------- TJSV ------------------+
                           |
                      Contract IR
                           |
                  public-admission check
                           ^
                           |
<product>-orm-core -- ores-orm-core parity/shape/codegen --> generated derivative artifacts
                           |
                           +--> private server-only Serde/model surfaces
                           +--> admitted server DTOs in <product>-lib-core
                           +--> admitted client-safe DTOs in <product>-pub-lib-core / <product>-clients
```

`*-orm-core` remains the private backend home for executable Diesel/SeaORM behavior. Public packages receive only explicitly admitted generated projections, never executable ORM code or database credentials/configuration.

## CLI boundary

Durable codegen, checks, validators, and audit tooling are Rust-first. The configuration contract is `.ores-orm.toml`. A production executable CLI must use the fleet `flags-2-env` argv boundary and `.cli-flags.toml`; ad-hoc argument parsing is not an accepted release path.

Generated output lives under `generated/` with provenance receipts and is reproducible from exact source bytes, normalized ORM IR, policy/options, tool version/revision, and retained contract evidence.

## Related repositories

- `ORESoftware/orm-core-template.rs`
- `ORESoftware/ores-contracts`
- `ORESoftware/ores-interfaces`
- `ORESoftware/typespec-json-schema-validator`
- `ORESoftware/ores-wit`
- `ORESoftware/flags-2-env`

## Derivative language packages

The ORM-first lane derives the same shape algebra into five deterministic artifacts:

- Rust Serde DTO source;
- TypeScript + Zod validators;
- Dart typed models with presence-aware JSON decoding;
- Gleam types plus dynamic decoders;
- the Draft 2020-12 JSON Schema witness.

Public generation is fail-closed. A table must opt into `public_surface = true`, every storage column must be classified as public, private, or secret, and public shapes are assembled only from explicit `public_read`, `public_create`, and `public_update` allowlists. Serde capability by itself never implies public exposure.

`emit::bundle` binds the language sources to the exact converged ORM IR, policy-derived shape, source digests, generator-option digest, and per-artifact SHA-256 values. A public bundle remains a **candidate** until TJSV verifies it against the exact owning TypeSpec + authored JSON Schema contract and retained Contract IR/receipt. Generation is not publication or admission.

## TJSV public admission

Digest-binding contract files to a public derivative is not semantic admission. The manifest keeps those states separate:

- `required`: a public shape has no contract evidence attached;
- `evidence_bound`: exact Contract IR and receipt bytes are hashed into generation evidence, but the derivative remains blocked;
- `admitted`: the exact Contract IR, TJSV projection manifest, and self-digesting `projection-verification-receipt/v1` passed local integrity/binding checks, the trusted projection declares the expected contract scope and runtime-validator scope, and the verified output digests exactly equal this bundle's Rust/TypeScript/Dart/Gleam/JSON-Schema bytes;
- `not_applicable`: the shape is private/server-only.

`TjsvAdmissionBinding::verify` recomputes the Contract IR `irId`, projection `manifestId`, and projection `verificationId` using TJSV's canonical object-key ordering; checks the peer-authority model, mandatory contract-admission coverage, parity-run identity, source digests, declaration scope, projection identity, runtime-validator closure, output closure, and receipt summary; and retains exact byte digests for all three evidence artifacts. The canonical projection id is a bounded TJSV-safe identity derived from SHA-256 of the exact table name plus the shape kind.

`bundle::emit_admitted` preserves the current exact-lineage gate: it requires the same converged ORM IR and validated policy used to derive the shape, plus an in-process verified admission capability, and proves that the TJSV-verified output path/digest set exactly matches the newly generated five-artifact bundle. Deserializing an admission manifest clears that in-process capability, so stored or fabricated JSON cannot be replayed directly as authorization to publish.

The admitted manifest format is `ores.orm-core.derivative-manifest/v3`. TypeSpec and independently authored JSON Schema remain the only contract authorities; Contract IR, projection manifests, runtime evidence, projection receipts, ORM policy evidence, and ORM derivatives remain downstream evidence.
