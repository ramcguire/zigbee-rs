use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::process::ExitCode;

fn workspace_root() -> PathBuf {
    // CARGO_MANIFEST_DIR is the xtask/ directory; its parent is the workspace root.
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask must be a direct child of the workspace root")
        .to_path_buf()
}

fn uv_available() -> bool {
    Command::new("uv")
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn collect_rs_files(dir: &Path, files: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_rs_files(&path, files);
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            files.push(path);
        }
    }
}

fn rustfmt_vectors(out_dir: &Path) -> ExitCode {
    let mut files = Vec::new();
    collect_rs_files(out_dir, &mut files);
    if files.is_empty() {
        return ExitCode::SUCCESS;
    }
    let mut cmd = Command::new("rustfmt");
    for f in &files {
        cmd.arg(f);
    }
    match cmd.status() {
        Ok(s) if s.success() => ExitCode::SUCCESS,
        Ok(s) => {
            eprintln!("rustfmt failed on generated vectors");
            ExitCode::from(s.code().unwrap_or(1) as u8)
        }
        Err(e) => {
            eprintln!("error running rustfmt: {e}");
            ExitCode::FAILURE
        }
    }
}

fn generate_vectors(root: &Path, check: bool) -> ExitCode {
    if !uv_available() {
        eprintln!(
            "error: `uv` not found.\n\
             Install: https://docs.astral.sh/uv/getting-started/installation/\n\
             Quick install (Unix): curl -LsSf https://astral.sh/uv/install.sh | sh"
        );
        return ExitCode::FAILURE;
    }

    let script = root.join("scripts/gen_vectors.py");
    let out_dir = root.join("zigbee-cluster-library/tests/vectors");

    if !script.exists() {
        eprintln!("error: script not found: {}", script.display());
        return ExitCode::FAILURE;
    }

    let mut cmd = Command::new("uv");
    cmd.arg("run").arg(&script).arg("--out").arg(&out_dir);

    if check {
        cmd.arg("--check");
    }

    let status = match cmd.status() {
        Ok(s) if s.success() => ExitCode::SUCCESS,
        Ok(s) => return ExitCode::from(s.code().unwrap_or(1) as u8),
        Err(e) => {
            eprintln!("error running uv: {e}");
            return ExitCode::FAILURE;
        }
    };

    if !check {
        return rustfmt_vectors(&out_dir);
    }

    status
}

fn main() -> ExitCode {
    let root = workspace_root();

    match std::env::args().nth(1).as_deref() {
        Some("generate-vectors") => generate_vectors(&root, false),
        Some("check-vectors") => generate_vectors(&root, true),
        Some(other) => {
            eprintln!("unknown subcommand: {other}");
            eprintln!("available: generate-vectors, check-vectors");
            ExitCode::FAILURE
        }
        None => {
            eprintln!("usage: cargo xtask <generate-vectors|check-vectors>");
            ExitCode::FAILURE
        }
    }
}
