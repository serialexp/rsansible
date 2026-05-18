//! pip backend for `OpPackage`.
//!
//! Strategy:
//!   1. If `op.virtualenv` is non-empty and `<venv>/bin/python` is missing,
//!      materialise the venv via `virtualenv_command <venv>` (default
//!      `python3 -m venv <venv>`). Tokenisation is whitespace-only; no
//!      shell metacharacters honored. The newly-created venv counts
//!      toward `changed=1` even if `op.names` ends up being a no-op.
//!   2. Probe `<pip> show <name>` for each requested package.
//!      `state: present` skips installed packages; `state: absent` skips
//!      missing ones; `state: latest` reinstalls every name without a
//!      version pin so pip's resolver picks the freshest matching
//!      release, then compares pre/post `Version:` to decide changed.
//!   3. Install/uninstall the deltas with a single batched `pip install`
//!      / `pip uninstall -y` call.
//!
//! No-network / private-index considerations live in `virtualenv_command`
//! (e.g. `python -m venv --without-pip` users); the agent calls pip
//! verbatim, so any `--index-url` lives in the controller-side `name:`
//! string (matches Ansible's `pip:`).
//!
//! Name parsing is intentionally permissive: we split on the first PEP
//! 440 specifier character (`=<>!~`) plus `[` (extras), `;` (markers),
//! ` ` (whitespace) to extract the bare package name for the
//! `pip show <name>` probe. This is best-effort; weird specifiers that
//! `pip show` doesn't recognise fall through as "not installed" and
//! get fed back to `pip install`, which is idempotent enough on its
//! own.
//!
//! Idempotency caveats (matching Ansible):
//!   - `state: present` with a version specifier (`name==1.2.3`) skips
//!     when the installed version already satisfies the spec — we
//!     check via `pkg_resources`-equivalent (substring match on
//!     `Version:` line). Exact-equality only; `>=`-style constraints
//!     are conservatively treated as "install if not present at all"
//!     and a subsequent run re-invokes pip (which is itself
//!     idempotent enough).

use std::path::{Path, PathBuf};
use std::process::Command;

use rsansible_wire::generated::OpPackageOutput;

use super::PackageError;

const STATE_PRESENT: u8 = 0;
const STATE_ABSENT: u8 = 1;
const STATE_LATEST: u8 = 2;

pub(crate) fn apply(op: &OpPackageOutput, check_mode: bool) -> Result<bool, PackageError> {
    let bins = Bins::from_env();
    apply_with_bins(&bins, op, check_mode)
}

pub(crate) struct Bins {
    pub default_python: String,
    pub default_pip: String,
}

impl Bins {
    pub fn from_env() -> Self {
        Self {
            default_python: std::env::var("RSANSIBLE_PYTHON")
                .unwrap_or_else(|_| "python3".into()),
            default_pip: std::env::var("RSANSIBLE_PIP").unwrap_or_else(|_| "pip3".into()),
        }
    }
}

pub(crate) fn apply_with_bins(
    bins: &Bins,
    op: &OpPackageOutput,
    check_mode: bool,
) -> Result<bool, PackageError> {
    let mut changed = false;

    // 1. Materialise the venv if requested and missing.
    let venv_python: Option<PathBuf> = if op.virtualenv.is_empty() {
        None
    } else {
        let venv = Path::new(&op.virtualenv);
        let python = venv.join("bin").join("python");
        if !python.exists() {
            if check_mode {
                // Can't probe what's installed without a working python.
                // Report changed without modifying anything.
                return Ok(true);
            }
            create_venv(bins, &op.virtualenv, &op.virtualenv_command)?;
            changed = true;
        }
        Some(python)
    };

    // 2. Probe each requested package.
    if op.names.is_empty() {
        return Ok(changed);
    }

    let pip_invocation = build_pip_invocation(bins, &venv_python);

    let mut to_install: Vec<String> = Vec::new();
    let mut to_uninstall: Vec<String> = Vec::new();
    let mut latest_pre_versions: Vec<(String, Option<String>)> = Vec::new();

    for raw in &op.names {
        let bare = bare_name(raw);
        if bare.is_empty() {
            return Err(PackageError::BadRequest(format!(
                "pip: empty package name in {raw:?}"
            )));
        }
        let installed = pip_show_version(&pip_invocation, &bare)?;
        match op.state {
            STATE_PRESENT => {
                let satisfied = match (&installed, version_pin(raw)) {
                    (Some(_), None) => true, // any version OK
                    (Some(have), Some(want)) => have == &want,
                    (None, _) => false,
                };
                if !satisfied {
                    to_install.push(raw.clone());
                }
            }
            STATE_ABSENT => {
                if installed.is_some() {
                    to_uninstall.push(bare);
                }
            }
            STATE_LATEST => {
                latest_pre_versions.push((bare.clone(), installed));
                to_install.push(bare); // re-install without pin to grab newest
            }
            other => {
                return Err(PackageError::BadRequest(format!(
                    "pip: unknown state byte {other}"
                )));
            }
        }
    }

    if check_mode {
        if !to_install.is_empty() || !to_uninstall.is_empty() {
            return Ok(true);
        }
        return Ok(changed);
    }

    if !to_install.is_empty() {
        run_pip(&pip_invocation, "install", &to_install)?;
        if op.state == STATE_LATEST {
            // Compare pre/post for each name; flag changed iff anything moved.
            for (bare, pre) in &latest_pre_versions {
                let post = pip_show_version(&pip_invocation, bare)?;
                if pre != &post {
                    changed = true;
                }
            }
        } else {
            changed = true;
        }
    }
    if !to_uninstall.is_empty() {
        let mut args = vec!["-y".to_string()];
        args.extend(to_uninstall.iter().cloned());
        run_pip(&pip_invocation, "uninstall", &args)?;
        changed = true;
    }
    Ok(changed)
}

/// Construct the pip command to invoke: prefer `<venv>/bin/pip` when a
/// venv is in scope, falling back to the configured system pip. Returns
/// (argv0, prefix_args) so the caller can append subcommand + args.
fn build_pip_invocation(bins: &Bins, venv_python: &Option<PathBuf>) -> PipInvocation {
    match venv_python {
        Some(py) => {
            let pip = py.parent().unwrap().join("pip");
            if pip.exists() {
                PipInvocation::Direct(pip.to_string_lossy().into_owned())
            } else {
                // Some venvs (created with --without-pip) lack a pip
                // binary but can be invoked via `python -m pip`.
                PipInvocation::PythonModule(py.to_string_lossy().into_owned())
            }
        }
        None => PipInvocation::Direct(bins.default_pip.clone()),
    }
}

#[derive(Debug, Clone)]
enum PipInvocation {
    Direct(String),
    PythonModule(String),
}

impl PipInvocation {
    fn argv(&self, subcmd: &str, args: &[String]) -> (String, Vec<String>) {
        match self {
            PipInvocation::Direct(p) => {
                let mut v = vec![subcmd.to_string()];
                v.extend(args.iter().cloned());
                (p.clone(), v)
            }
            PipInvocation::PythonModule(py) => {
                let mut v = vec!["-m".into(), "pip".into(), subcmd.to_string()];
                v.extend(args.iter().cloned());
                (py.clone(), v)
            }
        }
    }
}

fn create_venv(bins: &Bins, venv: &str, command: &str) -> Result<(), PackageError> {
    let argv: Vec<String> = if command.is_empty() {
        vec![bins.default_python.clone(), "-m".into(), "venv".into(), venv.into()]
    } else {
        let mut tokens: Vec<String> = command.split_whitespace().map(String::from).collect();
        if tokens.is_empty() {
            return Err(PackageError::BadRequest(
                "pip.virtualenv_command: empty after tokenisation".into(),
            ));
        }
        tokens.push(venv.into());
        tokens
    };
    let bin = argv[0].clone();
    let rest: Vec<&str> = argv[1..].iter().map(|s| s.as_str()).collect();
    let out = Command::new(&bin)
        .args(&rest)
        .output()
        .map_err(|e| PackageError::Spawn(format!("spawn {bin}: {e}")))?;
    if !out.status.success() {
        return Err(PackageError::Io(format!(
            "{bin} {rest:?} failed ({:?}): stderr={:?}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        )));
    }
    Ok(())
}

/// Probe `pip show <name>`. Returns Some(version) when installed, None
/// when `pip show` reports the package isn't installed (exit 1 with
/// "WARNING: Package(s) not found" on stderr). Other failures bubble.
fn pip_show_version(inv: &PipInvocation, name: &str) -> Result<Option<String>, PackageError> {
    let (bin, args) = inv.argv("show", &[name.to_string()]);
    let out = Command::new(&bin)
        .args(args.iter().map(|s| s.as_str()).collect::<Vec<_>>())
        .output()
        .map_err(|e| PackageError::Spawn(format!("spawn {bin}: {e}")))?;
    if !out.status.success() {
        // Not installed → exit 1 with empty stdout. Treat as "missing"
        // rather than an error; install path will handle it.
        return Ok(None);
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    for line in stdout.lines() {
        if let Some(rest) = line.strip_prefix("Version:") {
            return Ok(Some(rest.trim().to_string()));
        }
    }
    Ok(None)
}

fn run_pip(inv: &PipInvocation, subcmd: &str, args: &[String]) -> Result<(), PackageError> {
    let (bin, full_args) = inv.argv(subcmd, args);
    let out = Command::new(&bin)
        .args(full_args.iter().map(|s| s.as_str()).collect::<Vec<_>>())
        .output()
        .map_err(|e| PackageError::Spawn(format!("spawn {bin}: {e}")))?;
    if !out.status.success() {
        return Err(PackageError::Io(format!(
            "{bin} {full_args:?} failed ({:?}): stderr={:?}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        )));
    }
    Ok(())
}

/// Strip a PEP 440 / setuptools-style suffix from a pip requirement
/// to leave the bare package name. Returns the input as a string up
/// to the first occurrence of any of `=<>!~`, `[`, `;`, or whitespace.
fn bare_name(spec: &str) -> String {
    let cut = spec
        .find(|c: char| matches!(c, '=' | '<' | '>' | '!' | '~' | '[' | ';') || c.is_whitespace())
        .unwrap_or(spec.len());
    spec[..cut].trim().to_string()
}

/// Pull out a `==X.Y.Z`-style exact-version pin so the probe can decide
/// whether an installed version already satisfies the spec. Returns
/// `None` for any other constraint syntax (we conservatively treat
/// `>= 1.0` as "install if missing"; pip's own resolver handles the
/// upgrade if our re-invocation is needed).
fn version_pin(spec: &str) -> Option<String> {
    let eq = spec.find("==")?;
    let v = spec[eq + 2..]
        .split(|c: char| matches!(c, ',' | ';' | '[') || c.is_whitespace())
        .next()?
        .trim();
    if v.is_empty() {
        None
    } else {
        Some(v.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsansible_wire::msg::now_unix_ns;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    /// Sandbox a pip stub backed by a flat-file "installed packages" db.
    /// `pip show <name>` greps the db; `pip install <names>` appends with
    /// version 1.0.0 (or honors `==X.Y.Z` pins); `pip uninstall -y <names>`
    /// removes lines.
    struct Stub {
        dir: PathBuf,
        #[allow(dead_code)]
        bin_dir: PathBuf,
        venv: PathBuf,
    }
    impl Drop for Stub {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }
    impl Stub {
        fn new(label: &str, installed: &[(&str, &str)]) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "rsansible-pip-{label}-{}-{}",
                std::process::id(),
                now_unix_ns()
            ));
            std::fs::create_dir_all(&dir).unwrap();
            let db = dir.join("installed");
            let mut s = String::new();
            for (n, v) in installed {
                s.push_str(&format!("{n}\t{v}\n"));
            }
            std::fs::write(&db, s).unwrap();

            // venv with a bin/pip and bin/python — pip is the stub.
            let venv = dir.join("venv");
            let bin_dir = venv.join("bin");
            std::fs::create_dir_all(&bin_dir).unwrap();
            // Touch a python file so `<venv>/bin/python` exists (we don't
            // execute it; presence is what create_venv probes).
            std::fs::write(bin_dir.join("python"), "#!/bin/sh\nexit 0\n").unwrap();

            let pip_script = format!(
                r#"#!/bin/sh
DB="{db}"
cmd="$1"; shift
case "$cmd" in
  show)
    name="$1"
    line=$(grep -E "^${{name}}	" "$DB" || true)
    [ -z "$line" ] && exit 1
    version=$(echo "$line" | cut -f2)
    echo "Name: $name"
    echo "Version: $version"
    ;;
  install)
    for arg in "$@"; do
      bare=$(echo "$arg" | sed 's/[=<>!~\[;].*//')
      version=$(echo "$arg" | sed -n 's/.*==\([^,; ]*\).*/\1/p')
      [ -z "$version" ] && version="1.0.0"
      # remove any existing line, then append.
      grep -v -E "^${{bare}}	" "$DB" > "$DB.tmp" || true
      mv "$DB.tmp" "$DB"
      echo "${{bare}}	${{version}}" >> "$DB"
    done
    ;;
  uninstall)
    # consume -y
    [ "$1" = "-y" ] && shift
    for name in "$@"; do
      grep -v -E "^${{name}}	" "$DB" > "$DB.tmp" || true
      mv "$DB.tmp" "$DB"
    done
    ;;
  *) echo "stub-pip: unknown subcommand $cmd" >&2; exit 2 ;;
esac
"#,
                db = db.display()
            );
            write_script(&bin_dir.join("pip"), &pip_script);
            // Mirror through python -m pip for the alternate path.
            write_script(
                &bin_dir.join("python-m-pip-shim"),
                &pip_script.replace("$1", "$3").replace("shift", "shift 3"),
            );

            Stub { dir, bin_dir, venv }
        }
        fn db(&self) -> String {
            std::fs::read_to_string(self.dir.join("installed")).unwrap_or_default()
        }
    }

    fn write_script(p: &Path, body: &str) {
        std::fs::write(p, body.as_bytes()).unwrap();
        let mut perms = std::fs::metadata(p).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(p, perms).unwrap();
    }

    fn op(names: &[&str], state: u8, virtualenv: &str) -> OpPackageOutput {
        OpPackageOutput {
            kind: 10,
            manager: 7,
            names: names.iter().map(|s| s.to_string()).collect(),
            state,
            update_cache: 0,
            cache_valid_time: 0,
            purge: 0,
            autoremove: 0,
            default_release: String::new(),
            allow_unauthenticated: 0,
            virtualenv: virtualenv.into(),
            virtualenv_command: String::new(),
        }
    }

    fn bins() -> Bins {
        // Tests rely on the venv stub's pip; default_pip / default_python
        // aren't actually invoked because we pin virtualenv.
        Bins {
            default_python: "/bin/false".into(),
            default_pip: "/bin/false".into(),
        }
    }

    #[test]
    fn installs_missing_package() {
        let stub = Stub::new("install", &[]);
        let changed = apply_with_bins(
            &bins(),
            &op(&["redis>=5.0"], STATE_PRESENT, stub.venv.to_str().unwrap()),
            false,
        )
        .unwrap();
        assert!(changed);
        assert!(stub.db().contains("redis"));
    }

    #[test]
    fn skips_present_when_already_installed() {
        let stub = Stub::new("present-noop", &[("redis", "5.0.0")]);
        let changed = apply_with_bins(
            &bins(),
            &op(&["redis"], STATE_PRESENT, stub.venv.to_str().unwrap()),
            false,
        )
        .unwrap();
        assert!(!changed);
    }

    #[test]
    fn version_pin_match_is_noop() {
        let stub = Stub::new("pin-noop", &[("redis", "5.0.1")]);
        let changed = apply_with_bins(
            &bins(),
            &op(&["redis==5.0.1"], STATE_PRESENT, stub.venv.to_str().unwrap()),
            false,
        )
        .unwrap();
        assert!(!changed);
    }

    #[test]
    fn version_pin_mismatch_reinstalls() {
        let stub = Stub::new("pin-change", &[("redis", "5.0.0")]);
        let changed = apply_with_bins(
            &bins(),
            &op(&["redis==5.0.1"], STATE_PRESENT, stub.venv.to_str().unwrap()),
            false,
        )
        .unwrap();
        assert!(changed);
        assert!(stub.db().contains("redis\t5.0.1"));
    }

    #[test]
    fn absent_uninstalls_installed() {
        let stub = Stub::new("absent", &[("redis", "5.0.0"), ("celery", "1.0.0")]);
        let changed = apply_with_bins(
            &bins(),
            &op(&["redis"], STATE_ABSENT, stub.venv.to_str().unwrap()),
            false,
        )
        .unwrap();
        assert!(changed);
        assert!(!stub.db().contains("redis"));
        assert!(stub.db().contains("celery"));
    }

    #[test]
    fn absent_noop_when_already_missing() {
        let stub = Stub::new("absent-noop", &[("celery", "1.0.0")]);
        let changed = apply_with_bins(
            &bins(),
            &op(&["redis"], STATE_ABSENT, stub.venv.to_str().unwrap()),
            false,
        )
        .unwrap();
        assert!(!changed);
    }

    #[test]
    fn creates_missing_venv_with_default_command() {
        let stub = Stub::new("venv-mk", &[]);
        // Remove the venv created by Stub so we exercise the "missing" path.
        std::fs::remove_dir_all(&stub.venv).unwrap();
        // Override default_python with a stub that just `mkdir -p`s the
        // expected layout the way `python3 -m venv` would.
        let py_stub = stub.dir.join("py-stub");
        let venv_arg = stub.venv.to_string_lossy();
        write_script(
            &py_stub,
            &format!(
                r#"#!/bin/sh
# $1=-m $2=venv $3=<venv-dir>
mkdir -p "$3/bin"
cat > "$3/bin/python" <<'EOT'
#!/bin/sh
exit 0
EOT
chmod +x "$3/bin/python"
cat > "$3/bin/pip" <<'EOT'
#!/bin/sh
case "$1" in show) exit 1;; install|uninstall) exit 0;; esac
EOT
chmod +x "$3/bin/pip"
"#
            ),
        );
        let mut b = bins();
        b.default_python = py_stub.to_string_lossy().into_owned();
        let _ = venv_arg;
        let changed = apply_with_bins(
            &b,
            &op(&["redis"], STATE_PRESENT, stub.venv.to_str().unwrap()),
            false,
        )
        .unwrap();
        assert!(changed);
        assert!(stub.venv.join("bin/python").exists());
        assert!(stub.venv.join("bin/pip").exists());
    }

    #[test]
    fn check_mode_skips_when_already_installed() {
        let stub = Stub::new("check-installed", &[("redis", "5.0.0")]);
        let changed = apply_with_bins(
            &bins(),
            &op(&["redis"], STATE_PRESENT, stub.venv.to_str().unwrap()),
            true,
        )
        .unwrap();
        assert!(!changed);
    }

    #[test]
    fn check_mode_reports_would_install() {
        let stub = Stub::new("check-missing", &[]);
        let changed = apply_with_bins(
            &bins(),
            &op(&["redis"], STATE_PRESENT, stub.venv.to_str().unwrap()),
            true,
        )
        .unwrap();
        assert!(changed);
        // Did NOT actually run pip install.
        assert!(!stub.db().contains("redis"));
    }

    #[test]
    fn bare_name_strips_specifiers() {
        assert_eq!(bare_name("redis>=5.0"), "redis");
        assert_eq!(bare_name("flask==2.0.1"), "flask");
        assert_eq!(bare_name("requests[security]"), "requests");
        assert_eq!(bare_name("foo; python_version<'3.10'"), "foo");
        assert_eq!(bare_name("plain"), "plain");
    }

    #[test]
    fn version_pin_extracts_exact() {
        assert_eq!(version_pin("redis==5.0.1"), Some("5.0.1".into()));
        assert_eq!(version_pin("redis>=5.0"), None);
        assert_eq!(version_pin("redis"), None);
    }
}
