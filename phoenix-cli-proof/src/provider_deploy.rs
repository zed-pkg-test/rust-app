use anyhow::{bail, Context, Result};
use std::process::{Command, Stdio};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provider {
    Beamscale,
    AwsLambda,
    AwsLambdaManaged,
    GcpCloudRun,
}

impl Provider {
    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "beamscale" => Ok(Self::Beamscale),
            "aws-lambda" => Ok(Self::AwsLambda),
            "aws-lambda-managed" => Ok(Self::AwsLambdaManaged),
            "gcp-cloud-run" => Ok(Self::GcpCloudRun),
            other => bail!(
                "unsupported provider {other:?}; expected beamscale, aws-lambda, aws-lambda-managed, or gcp-cloud-run"
            ),
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Beamscale => "beamscale",
            Self::AwsLambda => "aws-lambda",
            Self::AwsLambdaManaged => "aws-lambda-managed",
            Self::GcpCloudRun => "gcp-cloud-run",
        }
    }
}

pub struct ExternalDeployOptions {
    pub provider: Provider,
    pub image: String,
    pub aws_function: Option<String>,
    pub gcp_service: Option<String>,
    pub region: String,
    pub gcp_project: Option<String>,
    pub bundle_sha256: String,
    pub dry_run: bool,
}

pub fn deploy(options: ExternalDeployOptions) -> Result<()> {
    if options.provider == Provider::Beamscale {
        bail!("internal error: BeamScale provider must use the native control-plane deploy path");
    }
    validate_immutable_image(&options.image)?;
    validate_sha256(&options.bundle_sha256)?;
    validate_region(&options.region)?;

    match options.provider {
        Provider::AwsLambda | Provider::AwsLambdaManaged => deploy_aws(options),
        Provider::GcpCloudRun => deploy_gcp(options),
        Provider::Beamscale => unreachable!(),
    }
}

fn deploy_aws(options: ExternalDeployOptions) -> Result<()> {
    let function = options
        .aws_function
        .as_deref()
        .context("--function is required for AWS providers")?;
    validate_target_name("AWS function", function)?;

    let update = vec![
        "aws".to_owned(),
        "lambda".to_owned(),
        "update-function-code".to_owned(),
        "--function-name".to_owned(),
        function.to_owned(),
        "--image-uri".to_owned(),
        options.image.clone(),
        "--region".to_owned(),
        options.region.clone(),
        "--no-cli-pager".to_owned(),
        "--output".to_owned(),
        "json".to_owned(),
    ];
    let wait = vec![
        "aws".to_owned(),
        "lambda".to_owned(),
        "wait".to_owned(),
        "function-updated".to_owned(),
        "--function-name".to_owned(),
        function.to_owned(),
        "--region".to_owned(),
        options.region.clone(),
        "--no-cli-pager".to_owned(),
    ];

    if options.dry_run {
        print_command("update AWS Lambda image", &update);
        print_command("wait for AWS Lambda update", &wait);
        eprintln!(
            "bmscl: dry run: AWS bundle tag would be sha256:{}",
            options.bundle_sha256
        );
        return Ok(());
    }

    run(&update, "update AWS Lambda image")?;
    run(&wait, "wait for AWS Lambda update")?;

    let arn_cmd = vec![
        "aws".to_owned(),
        "lambda".to_owned(),
        "get-function-configuration".to_owned(),
        "--function-name".to_owned(),
        function.to_owned(),
        "--region".to_owned(),
        options.region.clone(),
        "--query".to_owned(),
        "FunctionArn".to_owned(),
        "--output".to_owned(),
        "text".to_owned(),
        "--no-cli-pager".to_owned(),
    ];
    let arn = run_capture(&arn_cmd, "read AWS Lambda ARN")?;
    let arn = arn.trim();
    if !valid_arn(arn) {
        bail!("AWS returned an invalid Lambda function ARN");
    }
    let tags = format!(
        "bmscl-bundle-sha256={},bmscl-provider={}",
        options.bundle_sha256,
        options.provider.label()
    );
    run(
        &[
            "aws".to_owned(),
            "lambda".to_owned(),
            "tag-resource".to_owned(),
            "--resource".to_owned(),
            arn.to_owned(),
            "--tags".to_owned(),
            tags,
            "--region".to_owned(),
            options.region,
            "--no-cli-pager".to_owned(),
        ],
        "tag AWS Lambda bundle identity",
    )
}

fn deploy_gcp(options: ExternalDeployOptions) -> Result<()> {
    let service = options
        .gcp_service
        .as_deref()
        .context("--service is required for gcp-cloud-run")?;
    let project = options
        .gcp_project
        .as_deref()
        .context("--gcp-project or GOOGLE_CLOUD_PROJECT is required for gcp-cloud-run")?;
    validate_gcp_service(service)?;
    validate_gcp_project(project)?;
    let (left, right) = options.bundle_sha256.split_at(32);
    let labels =
        format!("bmscl-bundle-a={left},bmscl-bundle-b={right},bmscl-provider=gcp-cloud-run");
    let argv = vec![
        "gcloud".to_owned(),
        "run".to_owned(),
        "deploy".to_owned(),
        service.to_owned(),
        "--image".to_owned(),
        options.image,
        "--region".to_owned(),
        options.region,
        "--project".to_owned(),
        project.to_owned(),
        "--quiet".to_owned(),
        "--update-labels".to_owned(),
        labels,
        "--format".to_owned(),
        "json".to_owned(),
    ];
    if options.dry_run {
        print_command("deploy Cloud Run service", &argv);
        return Ok(());
    }
    run(&argv, "deploy Cloud Run service")
}

fn validate_immutable_image(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 512
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'.' | b'/' | b':' | b'@' | b'_' | b'-' | b'+')
        })
    {
        bail!("--image is not a safe OCI image reference");
    }
    let Some((repository, digest)) = value.rsplit_once("@sha256:") else {
        bail!("--image must be immutable and end in @sha256:<64-lowercase-hex>");
    };
    if repository.is_empty() || validate_sha256(digest).is_err() {
        bail!("--image must be immutable and end in @sha256:<64-lowercase-hex>");
    }
    Ok(())
}

fn validate_sha256(value: &str) -> Result<()> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        Ok(())
    } else {
        bail!("bundle SHA-256 must be 64 lowercase hexadecimal characters")
    }
}

fn validate_target_name(label: &str, value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        bail!("{label} contains unsupported characters");
    }
    Ok(())
}

fn validate_region(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        bail!("provider region contains unsupported characters");
    }
    Ok(())
}

fn validate_gcp_service(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 63
        || !value.as_bytes()[0].is_ascii_lowercase()
        || !value.as_bytes()[value.len() - 1].is_ascii_alphanumeric()
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        bail!("GCP Cloud Run service contains unsupported characters");
    }
    Ok(())
}

fn validate_gcp_project(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 128
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b':')
        })
    {
        bail!("GCP project contains unsupported characters");
    }
    Ok(())
}

fn valid_arn(value: &str) -> bool {
    value.starts_with("arn:")
        && !value.is_empty()
        && !value.bytes().any(|byte| matches!(byte, b'\r' | b'\n' | 0))
}

fn run(argv: &[String], what: &str) -> Result<()> {
    let (program, args) = argv.split_first().context("empty provider command")?;
    print_command(what, argv);
    let status = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .with_context(|| format!("launch {program}"))?;
    if !status.success() {
        bail!("{what} failed with {status}");
    }
    Ok(())
}

fn run_capture(argv: &[String], what: &str) -> Result<String> {
    let (program, args) = argv.split_first().context("empty provider command")?;
    let output = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .with_context(|| format!("launch {program}"))?;
    if !output.status.success() {
        bail!("{what} failed with {}", output.status);
    }
    if output.stdout.len() > 4096 {
        bail!("{what} returned an oversized response");
    }
    String::from_utf8(output.stdout).context("provider command returned non-UTF-8 output")
}

fn print_command(what: &str, argv: &[String]) {
    eprintln!("bmscl: {what}: {}", render(argv));
}

fn render(argv: &[String]) -> String {
    argv.iter()
        .map(|arg| {
            if arg
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "-._/:=@+,".contains(c))
            {
                arg.clone()
            } else {
                format!("{arg:?}")
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_names_are_closed() {
        assert_eq!(Provider::parse("beamscale").unwrap(), Provider::Beamscale);
        assert_eq!(Provider::parse("aws-lambda").unwrap(), Provider::AwsLambda);
        assert_eq!(
            Provider::parse("aws-lambda-managed").unwrap(),
            Provider::AwsLambdaManaged
        );
        assert_eq!(
            Provider::parse("gcp-cloud-run").unwrap(),
            Provider::GcpCloudRun
        );
        assert!(Provider::parse("other").is_err());
    }

    #[test]
    fn provider_images_must_be_digest_pinned() {
        assert!(
            validate_immutable_image(&format!("registry.example/x@sha256:{}", "a".repeat(64)))
                .is_ok()
        );
        assert!(validate_immutable_image("registry.example/x:latest").is_err());
        assert!(validate_immutable_image("x\nRUN evil").is_err());
    }

    #[test]
    fn cloud_run_service_is_lowercase_dns_like() {
        assert!(validate_gcp_service("billing-api").is_ok());
        assert!(validate_gcp_service("BillingApi").is_err());
    }

    #[test]
    fn aws_function_name_respects_lambda_limit() {
        assert!(validate_target_name("AWS function", &"a".repeat(64)).is_ok());
        assert!(validate_target_name("AWS function", &"a".repeat(65)).is_err());
        assert!(validate_target_name("AWS function", "billing_api-v2").is_ok());
        assert!(validate_target_name("AWS function", "billing.api").is_err());
        assert!(validate_target_name("AWS function", "billing/api").is_err());
    }
}
