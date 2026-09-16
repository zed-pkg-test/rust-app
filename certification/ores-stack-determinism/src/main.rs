use std::{env, fs, path::PathBuf, process};

use ores_api_docs::{
    materialize_finalized_page_build, read_page_build_manifest, write_page_build_manifest,
    write_page_build_outputs,
};

fn main() {
    let root = unique_temp();
    if root.exists() {
        fs::remove_dir_all(&root).unwrap();
    }

    let dynamic = root.join("src/pages/users/[id]");
    let static_new = root.join("src/pages/users/new");
    fs::create_dir_all(&dynamic).unwrap();
    fs::create_dir_all(&static_new).unwrap();

    fs::write(
        dynamic.join("page.rs"),
        r#"#[ores_page(renderer = "mash", delivery = "ssr_only", render = "dynamic", title = "Dynamic user")]
pub async fn page() {}
"#,
    )
    .unwrap();
    fs::write(dynamic.join("style.css"), b"main { min-height: 1px; }\n").unwrap();
    fs::write(
        static_new.join("page.rs"),
        r#"#[ores_page(renderer = "mash", delivery = "ssr_only", render = "dynamic", title = "New user")]
pub async fn page() {}
"#,
    )
    .unwrap();

    let pass_a = write_page_build_outputs(&root, &root.join(".ores-stack/a")).expect("pass a");
    let pass_b = write_page_build_outputs(&root, &root.join(".ores-stack/b")).expect("pass b");

    let manifest_a = fs::read(&pass_a.manifest_path).unwrap();
    let manifest_b = fs::read(&pass_b.manifest_path).unwrap();
    assert_eq!(manifest_a, manifest_b, "page manifests must be byte-identical");

    let glue_a = fs::read(&pass_a.compile_glue_path).unwrap();
    let glue_b = fs::read(&pass_b.compile_glue_path).unwrap();
    assert_eq!(glue_a, glue_b, "generated router glue must be byte-identical");

    let parsed = read_page_build_manifest(&pass_a.manifest_path).unwrap();
    let paths = parsed
        .routes
        .iter()
        .map(|route| route.canonical_path.as_str())
        .collect::<Vec<_>>();
    assert_eq!(paths, vec!["/users/new", "/users/{id}"], "static route must precede dynamic sibling");

    let rerun_a = pass_a
        .rerun_if_changed
        .iter()
        .map(|path| path.strip_prefix(&root).unwrap_or(path).to_string_lossy().replace('\\', "/"))
        .collect::<Vec<_>>();
    let mut sorted = rerun_a.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(rerun_a, sorted, "rerun inputs must be sorted and deduplicated");
    assert!(rerun_a.iter().any(|path| path.ends_with("src/pages/users/[id]/style.css")));

    let assets_a = sorted_file_names(&pass_a.manifest_path.parent().unwrap().join("page-assets"));
    let assets_b = sorted_file_names(&pass_b.manifest_path.parent().unwrap().join("page-assets"));
    assert_eq!(assets_a, assets_b, "content-addressed assets must be deterministic");
    assert_eq!(assets_a.len(), 1);
    assert!(assets_a[0].starts_with("page-"));
    assert!(assets_a[0].ends_with(".css"));

    reject_asset_path_traversal(&root, &pass_a.manifest_path);

    fs::remove_dir_all(&root).unwrap();
    println!("zed-pkg-test ores-stack determinism and traversal smoke passed");
}

fn reject_asset_path_traversal(root: &std::path::Path, valid_manifest: &std::path::Path) {
    let mut manifest = read_page_build_manifest(valid_manifest).unwrap();
    let css = manifest
        .routes
        .iter_mut()
        .find_map(|route| route.css.as_mut())
        .expect("fixture has css");
    css.output_file = "../escape.css".to_owned();

    let malicious_manifest = root.join(".ores-stack/malicious-manifest.json");
    write_page_build_manifest(&malicious_manifest, &manifest).unwrap();
    let asset_dir = valid_manifest.parent().unwrap().join("page-assets");
    let error = materialize_finalized_page_build(
        root,
        &root.join(".ores-stack/malicious-materialized"),
        &malicious_manifest,
        &asset_dir,
    )
    .expect_err("path traversal asset name must fail closed");
    let message = error.to_string();
    assert!(message.contains("not a safe basename"), "{message}");
    assert!(!root.join(".ores-stack/escape.css").exists());
}

fn sorted_file_names(dir: &std::path::Path) -> Vec<String> {
    let mut names = fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    names.sort();
    names
}

fn unique_temp() -> PathBuf {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    env::temp_dir().join(format!("zed-ores-stack-determinism-{}-{now}", process::id()))
}
