mod deploy;
mod dev;
mod docs_manifest;
mod durable_objects;
mod phoenix;
mod provider_bundle;
mod provider_deploy;
mod workspace;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use std::{env, path::PathBuf, process::Command};

#[derive(Parser)]
#[command(name = "bmscl", version, about = "BeamScale developer CLI")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Deploy a tenant-dedicated Durable Object / critical-section worker.
    DurableObjects {
        #[command(subcommand)]
        command: DurableObjectCommands,
    },
    /// Run the local development server. Rust mode restarts the Erlang OS process after accepted changes.
    Dev {
        #[arg(default_value = ".")]
        project: PathBuf,
        #[arg(long, default_value_t = 250)]
        poll_ms: u64,
        #[arg(long)]
        module: Option<String>,
    },
    /// Run Hosted Gleam admission checks without compiling.
    Check {
        #[arg(default_value = ".")]
        project: PathBuf,
        #[arg(long)]
        policy: Option<PathBuf>,
        #[arg(long)]
        worker_config: Option<PathBuf>,
        #[arg(long)]
        deny_cpu_loops: bool,
    },
    /// Recursively compile admitted Lambda and middleware Gleam units.
    #[command(alias = "compile")]
    Build {
        #[arg(default_value = ".")]
        project: PathBuf,
        #[arg(long, default_value = "dist")]
        out_dir: PathBuf,
        #[arg(long)]
        policy: Option<PathBuf>,
        #[arg(long)]
        worker_config: Option<PathBuf>,
        #[arg(long)]
        deny_cpu_loops: bool,
        /// Continue workspace builds past units explicitly rejected by the canonical admission report.
        /// Infrastructure/compiler/final-artifact verification failures remain fatal.
        #[arg(long)]
        filter_unsafe: bool,
    },
    /// Compile, sign, and emit a deterministic deployment bundle.
    Package {
        #[arg(default_value = ".")]
        project: PathBuf,
        #[arg(long, default_value = "dist")]
        out_dir: PathBuf,
        #[arg(long)]
        policy: Option<PathBuf>,
        #[arg(long)]
        worker_config: Option<PathBuf>,
        #[arg(long)]
        deny_cpu_loops: bool,
        /// Ed25519 32-byte signing seed file encoded as 64 hex characters.
        #[arg(long)]
        signing_key: Option<PathBuf>,
        /// Stable build-service signing key identifier.
        #[arg(long)]
        key_id: Option<String>,
        /// Explicitly permit unsigned local/development output.
        #[arg(long)]
        unsigned: bool,
    },
    /// Emit the provider-neutral api-docs lambda deployment manifest from admitted artifacts and one immutable route snapshot.
    DocsManifest {
        /// Root containing compiler-produced Lambda artifacts.
        #[arg(default_value = "dist")]
        artifact_dir: PathBuf,
        /// Immutable ores.routes.v1 snapshot whose targets must match admitted artifact digests.
        #[arg(long)]
        route_manifest: PathBuf,
        /// Stable API-docs service name.
        #[arg(long)]
        service: String,
        /// Canonical api-docs route-map contract SHA-256.
        #[arg(long)]
        contract_sha256: String,
        /// Output file. Omit to write deterministic JSON to stdout.
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Verify artifacts, routes, and middleware order into an immutable provider bundle.
    ProviderBundle {
        #[arg(default_value = "dist")]
        artifact_dir: PathBuf,
        /// Optional immutable ores.routes.v1 snapshot. When omitted, derive ANY /<lambda-name> routes using the same convention as dev mode.
        #[arg(long)]
        routes: Option<PathBuf>,
        #[arg(long, default_value = ".bmscl-provider")]
        out: PathBuf,
        #[arg(long, default_value_t = 1)]
        generation: u64,
        /// Middleware name in execution order. Repeat to specify explicit order.
        #[arg(long = "middleware")]
        middleware_order: Vec<String>,
        #[arg(long)]
        public_key: Option<String>,
        #[arg(long)]
        key_id: Option<String>,
    },
    /// Inspect a Phoenix router and optional Endpoint socket table, then emit a deterministic Firecracker route plan.
    PhoenixPlan {
        #[arg(default_value = ".")]
        project: PathBuf,
        /// Fully-qualified Phoenix router module, for example MyAppWeb.Router.
        #[arg(long)]
        router: String,
        /// Optional Phoenix Endpoint module. When supplied, BeamScale inspects __sockets__/0 and discovers websocket paths.
        #[arg(long)]
        endpoint: Option<String>,
        /// Additional WebSocket endpoint path. Repeat for explicit/fallback entries.
        #[arg(long = "socket-path")]
        socket_paths: Vec<String>,
        /// Output file. Omit to write JSON to stdout.
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Verify selected compiler artifacts locally using the canonical compiler verifier.
    Verify {
        #[arg(default_value = "dist")]
        artifact_dir: PathBuf,
        /// Verify only this Lambda. Repeat to select more than one.
        #[arg(long = "lambda")]
        lambdas: Vec<String>,
        /// Verify only this middleware unit. Repeat to select more than one.
        #[arg(long = "middleware")]
        middleware: Vec<String>,
        #[arg(long)]
        public_key: Option<String>,
        #[arg(long)]
        key_id: Option<String>,
    },
    /// Verify locally, then deploy only typed units whose signed build digest changed.
    Deploy {
        /// Root containing compiler-produced Lambda and/or middleware artifacts.
        #[arg(default_value = "dist")]
        artifact_dir: PathBuf,
        /// Stable project slug. Defaults to BMSCL_PROJECT or the current directory name.
        #[arg(long)]
        project: Option<String>,
        /// Deployment provider. BeamScale keeps the current admin API path; external providers package the verified artifacts into a trusted runtime image.
        #[arg(long, default_value = "beamscale")]
        provider: String,
        /// Immutable OCI image URI for external providers; must use @sha256:<digest>.
        #[arg(long)]
        image: Option<String>,
        /// provider-bundle.json emitted by `bmscl provider-bundle`.
        #[arg(long)]
        bundle: Option<PathBuf>,
        /// Existing AWS Lambda function name.
        #[arg(long = "function")]
        aws_function: Option<String>,
        /// Existing GCP Cloud Run service name.
        #[arg(long)]
        service: Option<String>,
        /// Provider region for AWS Lambda or Cloud Run.
        #[arg(long)]
        region: Option<String>,
        /// GCP project. Defaults to GOOGLE_CLOUD_PROJECT.
        #[arg(long)]
        gcp_project: Option<String>,
        /// Deployment environment. Defaults to BMSCL_ENVIRONMENT or production.
        #[arg(long)]
        environment: Option<String>,
        /// Deploy only this Lambda. Repeat to select more than one.
        #[arg(long = "lambda")]
        lambdas: Vec<String>,
        /// Deploy only this middleware unit. Repeat to select more than one.
        #[arg(long = "middleware")]
        middleware: Vec<String>,
        /// Explicitly request the default changed-only behavior.
        #[arg(long, conflicts_with = "force")]
        changed: bool,
        /// Re-apply selected units even when their build digests match.
        #[arg(long)]
        force: bool,
        /// Print the server-authoritative plan without uploading or applying it.
        #[arg(long)]
        dry_run: bool,
        /// Full-tree synchronization: tombstone remote units missing from the complete local artifact tree.
        #[arg(long, conflicts_with_all = ["lambdas", "middleware"])]
        prune: bool,
        /// Git commit recorded with changed targets. Defaults to git rev-parse HEAD.
        #[arg(long)]
        git_commit: Option<String>,
        /// Admin control-plane URL. Defaults to BMSCL_ADMIN_API_URL or localhost:8181.
        #[arg(long)]
        api_url: Option<String>,
        /// Trusted build-service Ed25519 public key; defaults to BMSCL_BUILD_PUBLIC_KEY.
        #[arg(long)]
        public_key: Option<String>,
        /// Require this attestation key ID while verifying selected artifacts.
        #[arg(long)]
        key_id: Option<String>,
    },
}

#[derive(Subcommand)]
enum DurableObjectCommands {
    /// Build and package the configured Erlang/Gleam Durable Object artifact.
    Build {
        #[arg(long, default_value = ".bmscl-durable-objects.toml")]
        config: PathBuf,
        #[arg(long)]
        signing_key: Option<PathBuf>,
        #[arg(long)]
        key_id: Option<String>,
        #[arg(long)]
        unsigned: bool,
    },
    Deploy {
        #[arg(long, default_value = ".bmscl-durable-objects.toml")]
        config: PathBuf,
        #[arg(long)]
        api_url: Option<String>,
        /// Admin API used for signed artifact admission before activation.
        #[arg(long)]
        admin_api_url: Option<String>,
        #[arg(long)]
        dry_run: bool,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::DurableObjects { command } => match command {
            DurableObjectCommands::Build {
                config,
                signing_key,
                key_id,
                unsigned,
            } => durable_objects::build(durable_objects::BuildOptions {
                config,
                signing_key,
                key_id,
                unsigned,
            }),
            DurableObjectCommands::Deploy {
                config,
                api_url,
                admin_api_url,
                dry_run,
            } => durable_objects::deploy(durable_objects::DeployOptions {
                config,
                api_url: api_url
                    .or_else(|| env::var("BMSCL_API_URL").ok())
                    .unwrap_or_else(|| "http://127.0.0.1:8081".into()),
                admin_api_url: admin_api_url
                    .or_else(|| env::var("BMSCL_ADMIN_API_URL").ok())
                    .unwrap_or_else(|| "http://127.0.0.1:8181".into()),
                dry_run,
            }),
        },
        Commands::Dev {
            project,
            poll_ms,
            module,
        } => dev::run(dev::DevOptions {
            project,
            poll_ms,
            module,
        }),
        Commands::Check {
            project,
            policy,
            worker_config,
            deny_cpu_loops,
        } => run_compiler(
            "check",
            &project,
            None,
            policy.as_deref(),
            worker_config.as_deref(),
            deny_cpu_loops,
            None,
            None,
        ),
        Commands::Build {
            project,
            out_dir,
            policy,
            worker_config,
            deny_cpu_loops,
            filter_unsafe,
        } => workspace::build_tree(workspace::BuildOptions {
            project,
            out_dir,
            policy,
            worker_config,
            deny_cpu_loops,
            filter_unsafe: filter_unsafe || env_flag("BMSCL_FILTER_UNSAFE"),
        }),
        Commands::Package {
            project,
            out_dir,
            policy,
            worker_config,
            deny_cpu_loops,
            signing_key,
            key_id,
            unsigned,
        } => {
            if unsigned && (signing_key.is_some() || key_id.is_some()) {
                bail!("--unsigned cannot be combined with --signing-key or --key-id");
            }
            if !unsigned && (signing_key.is_none() || key_id.is_none()) {
                bail!(
                    "production package requires --signing-key and --key-id; pass --unsigned only for local/development artifacts"
                );
            }
            run_compiler(
                "package",
                &project,
                Some(&out_dir),
                policy.as_deref(),
                worker_config.as_deref(),
                deny_cpu_loops,
                signing_key.as_deref(),
                key_id.as_deref(),
            )
        }
        Commands::DocsManifest {
            artifact_dir,
            route_manifest,
            service,
            contract_sha256,
            output,
        } => docs_manifest::emit(docs_manifest::DocsManifestOptions {
            artifact_dir,
            route_manifest,
            service,
            contract_sha256,
            output,
        }),
        Commands::ProviderBundle {
            artifact_dir,
            routes,
            out,
            generation,
            middleware_order,
            public_key,
            key_id,
        } => {
            provider_bundle::build(provider_bundle::BuildOptions {
                artifact_dir,
                routes,
                out_dir: out,
                generation,
                middleware_order,
                public_key: deploy::trusted_public_key(public_key)?,
                key_id,
            })?;
            Ok(())
        }
        Commands::PhoenixPlan {
            project,
            router,
            endpoint,
            socket_paths,
            output,
        } => phoenix::emit(phoenix::PhoenixPlanOptions {
            project,
            router,
            endpoint,
            socket_paths,
            output,
        }),
        Commands::Verify {
            artifact_dir,
            lambdas,
            middleware,
            public_key,
            key_id,
        } => deploy::verify(deploy::VerifyOptions {
            artifact_dir,
            lambdas,
            middleware,
            public_key: deploy::trusted_public_key(public_key)?,
            key_id,
        }),
        Commands::Deploy {
            artifact_dir,
            project,
            provider,
            image,
            bundle,
            aws_function,
            service,
            region,
            gcp_project,
            environment,
            lambdas,
            middleware,
            changed,
            force,
            dry_run,
            prune,
            git_commit,
            api_url,
            public_key,
            key_id,
        } => {
            let provider = provider_deploy::Provider::parse(&provider)?;
            let public_key = deploy::trusted_public_key(public_key)?;
            if provider == provider_deploy::Provider::Beamscale {
                deploy::deploy(deploy::DeployOptions {
                    artifact_dir,
                    project: resolve_project(project)?,
                    environment: environment
                        .or_else(|| env::var("BMSCL_ENVIRONMENT").ok())
                        .unwrap_or_else(|| "production".into()),
                    lambdas,
                    middleware,
                    force,
                    dry_run,
                    prune,
                    git_commit: git_commit.or_else(deploy::current_git_commit),
                    api_url: api_url
                        .or_else(|| env::var("BMSCL_ADMIN_API_URL").ok())
                        .unwrap_or_else(|| "http://127.0.0.1:8181".into()),
                    token: env::var("BMSCL_ADMIN_TOKEN").ok(),
                    public_key,
                    key_id,
                })
            } else {
                if prune || changed || force {
                    bail!(
                        "--prune, --changed and --force are BeamScale control-plane options and cannot be used with off-platform providers"
                    );
                }
                if !lambdas.is_empty() || !middleware.is_empty() {
                    bail!(
                        "--lambda/--middleware focused deploy is unavailable off-platform; deploy the complete verified provider bundle"
                    );
                }
                deploy::verify(deploy::VerifyOptions {
                    artifact_dir: artifact_dir.clone(),
                    lambdas: Vec::new(),
                    middleware: Vec::new(),
                    public_key,
                    key_id,
                })?;
                let bundle = bundle.context(
                    "--bundle is required for external providers; create it with bmscl provider-bundle",
                )?;
                let bundle_sha256 = provider_bundle::verify_for_deploy(&bundle, &artifact_dir)?;
                provider_deploy::deploy(provider_deploy::ExternalDeployOptions {
                    provider,
                    image: image.context("--image is required for external providers")?,
                    aws_function,
                    gcp_service: service,
                    region: region.context("--region is required for external providers")?,
                    gcp_project: gcp_project.or_else(|| env::var("GOOGLE_CLOUD_PROJECT").ok()),
                    bundle_sha256,
                    dry_run,
                })
            }
        }
    }
}

fn derive_project_name() -> Result<String> {
    env::current_dir()?
        .file_name()
        .and_then(|name| name.to_str())
        .map(str::to_string)
        .context("cannot derive project name from current directory; pass --project")
}

fn resolve_project(argument: Option<String>) -> Result<String> {
    match argument.or_else(|| env::var("BMSCL_PROJECT").ok()) {
        Some(project) if !project.is_empty() => Ok(project),
        Some(_) => bail!("project must not be empty"),
        None => derive_project_name(),
    }
}

fn env_flag(name: &str) -> bool {
    env::var(name)
        .ok()
        .map(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "t" | "yes" | "y" | "on"
            )
        })
        .unwrap_or(false)
}

#[allow(clippy::too_many_arguments)]
fn run_compiler(
    subcommand: &str,
    project: &std::path::Path,
    out_dir: Option<&std::path::Path>,
    policy: Option<&std::path::Path>,
    worker_config: Option<&std::path::Path>,
    deny_cpu_loops: bool,
    signing_key: Option<&std::path::Path>,
    key_id: Option<&str>,
) -> Result<()> {
    let compiler = compiler_binary();
    let mut command = Command::new(&compiler);
    command.arg(subcommand).arg(project);
    if let Some(out_dir) = out_dir {
        command.arg("--out-dir").arg(out_dir);
    }
    if let Some(policy) = policy {
        command.arg("--policy").arg(policy);
    }
    if let Some(worker_config) = worker_config {
        command.arg("--worker-config").arg(worker_config);
    }
    if deny_cpu_loops {
        command.arg("--deny-cpu-loops");
    }
    if let Some(signing_key) = signing_key {
        command.arg("--signing-key").arg(signing_key);
    }
    if let Some(key_id) = key_id {
        command.arg("--key-id").arg(key_id);
    }
    let status = command
        .status()
        .with_context(|| format!("launch {compiler}"))?;
    if !status.success() {
        bail!("{compiler} {subcommand} failed with {status}");
    }
    Ok(())
}

fn compiler_binary() -> String {
    env::var("BMSCL_COMPILER").unwrap_or_else(|_| "bmscl-compiler".into())
}
