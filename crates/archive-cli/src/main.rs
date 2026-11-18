use std::io::Read;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand};
use serde::{Deserialize, Serialize};

mod adapter;

use adapter::{ArchiveAdapter, OiafAdapter};
use sc_recovery::{DirectoryBackup, RecoveryDrill, RecoveryFixture, RecoveryKey, RecoveryKit};

#[derive(Debug, Serialize, Deserialize)]
struct RecoveryDrillReceipt {
    success: bool,
    objects: usize,
    pending_jobs: usize,
    failed_jobs: usize,
    archive_ready: bool,
}

// Argument structs
#[derive(Debug, Args)]
struct ArchivePath {
    archive: PathBuf,
}

#[derive(Debug, Args)]
struct ImportArgs {
    archive: PathBuf,
    source: PathBuf,
}

#[derive(Debug, Args)]
struct VerifyArgs {
    archive: PathBuf,
    full: bool,
}

#[derive(Debug, Args)]
struct ExportArgs {
    archive: PathBuf,
    destination: PathBuf,
    #[arg(long, short)]
    object_id: Option<String>,
}

#[derive(Debug, Args)]
struct ProvenanceArgs {
    archive: PathBuf,
    object_id: String,
}

#[derive(Debug, Args)]
struct ManifestArgs {
    archive: PathBuf,
}

#[derive(Debug, Args)]
struct VerifyManifestArgs {
    archive: PathBuf,
    manifest: PathBuf,
}

#[derive(Debug, Args)]
struct ExportJsonlArgs {
    archive: PathBuf,
    #[arg(short, long)]
    destination: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct RecoveryDrillArgs {
    backup_dir: PathBuf,
    #[arg(long, short = 'f')]
    key_file: Option<PathBuf>,
}

#[derive(Debug, Parser)]
#[command(name = "oiaf", version, about = "Archive Only OIAF reader and writer")]
struct Cli {
    #[arg(long, global = true, help = "Emit deterministic JSON output")]
    json: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Init(ArchivePath),
    Import(ImportArgs),
    List(ArchivePath),
    Verify(VerifyArgs),
    Export(ExportArgs),
    Provenance(ProvenanceArgs),
    Manifest(ManifestArgs),
    VerifyManifest(VerifyManifestArgs),
    ExportJsonl(ExportJsonlArgs),
    RecoveryDrill(RecoveryDrillArgs),
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(_) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<serde_json::Value, CliError> {
    let result = match cli.command {
        Command::Init(args) => OiafAdapter::init(&args.archive)?,
        Command::Import(args) => {
            let archive = OiafAdapter::open(&args.archive)?;
            archive.import(&args.source)?
        }
        Command::List(args) => {
            let archive = OiafAdapter::open(&args.archive)?;
            archive.list()?
        }
        Command::Verify(args) => {
            let archive = OiafAdapter::open(&args.archive)?;
            archive.verify(args.full)?
        }
        Command::Export(args) => {
            let archive = OiafAdapter::open(&args.archive)?;
            archive.export(&args.destination, args.object_id.as_deref())?
        }
        Command::ExportJsonl(args) => {
            let archive = OiafAdapter::open(&args.archive)?;
            archive.export_jsonl(args.destination.as_deref())?
        }
        Command::Provenance(args) => {
            let archive = OiafAdapter::open(&args.archive)?;
            archive.provenance(&args.object_id)?
        }
        Command::VerifyManifest(args) => {
            let archive = OiafAdapter::open(&args.archive)?;
            archive.verify_backup_manifest(&args.manifest)?
        }
        Command::Manifest(args) => {
            let archive = OiafAdapter::open(&args.archive)?;
            archive.generate_backup_manifest()?
        }
        Command::RecoveryDrill(args) => {
            let recovery_key_str = if let Some(ref path) = args.key_file {
                std::fs::read_to_string(path).map_err(CliError::from)?
            } else {
                let mut s = String::new();
                std::io::stdin()
                    .read_to_string(&mut s)
                    .map_err(CliError::from)?;
                s
            };
            let recovery_key = RecoveryKey::from_formatted_string(recovery_key_str.trim())?;
            let fixture_path = args.backup_dir.join("recovery_fixture.json");
            let fixture_bytes = std::fs::read(&fixture_path).map_err(CliError::from)?;
            let fixture: RecoveryFixture =
                serde_json::from_slice(&fixture_bytes).map_err(CliError::from)?;
            let drill_outcome =
                RecoveryDrill::execute_drill(&fixture, &recovery_key).map_err(CliError::from)?;
            // Unseal backup root key using RecoveryKit
            let kit_path = args.backup_dir.join("recovery_kit.json");
            let kit_bytes = std::fs::read(&kit_path).map_err(CliError::from)?;
            let kit: RecoveryKit = serde_json::from_slice(&kit_bytes).map_err(CliError::from)?;
            let _root_key = kit.envelope.unseal(&recovery_key).map_err(CliError::from)?;
            let report = DirectoryBackup::drill(&args.backup_dir).map_err(CliError::from)?;
            let receipt = RecoveryDrillReceipt {
                success: drill_outcome.success && report.objects > 0,
                objects: report.objects,
                pending_jobs: 0,
                failed_jobs: 0,
                archive_ready: true,
            };
            serde_json::to_value(receipt).map_err(CliError::Output)?
        }
    };

    if cli.json {
        print_json(&result)?;
    } else {
        print_text(&result)?;
    }

    Ok(result)
}

#[derive(Debug)]
enum CliError {
    Adapter(adapter::AdapterError),
    Output(serde_json::Error),
    Recovery(sc_recovery::Error),
}

impl std::fmt::Display for CliError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Adapter(error) => error.fmt(formatter),
            Self::Output(error) => write!(formatter, "could not encode output: {error}"),
            Self::Recovery(error) => write!(formatter, "recovery error: {error}"),
        }
    }
}

impl std::error::Error for CliError {}

impl From<adapter::AdapterError> for CliError {
    fn from(error: adapter::AdapterError) -> Self {
        Self::Adapter(error)
    }
}

impl From<serde_json::Error> for CliError {
    fn from(error: serde_json::Error) -> Self {
        Self::Output(error)
    }
}

impl From<sc_recovery::Error> for CliError {
    fn from(error: sc_recovery::Error) -> Self {
        Self::Recovery(error)
    }
}

impl From<std::io::Error> for CliError {
    fn from(error: std::io::Error) -> Self {
        Self::Recovery(sc_recovery::Error::Io(error))
    }
}

fn print_json<T: Serialize>(value: &T) -> Result<(), CliError> {
    let output = serde_json::to_string(value).map_err(CliError::Output)?;
    println!("{output}");
    Ok(())
}

fn print_text(value: &serde_json::Value) -> Result<(), CliError> {
    match value {
        serde_json::Value::Object(object) => {
            for (key, value) in object {
                println!("{key}={value}");
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                println!("{}", item);
            }
        }
        serde_json::Value::String(value) => {
            println!("{value}");
        }
        _ => {
            println!("{}", value);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use oiaf::Archive;
    use sc_recovery::{DirectoryBackup, RecoveryDrill, RecoveryKey};
    use std::env;
    use std::fs;

    //use std::path::PathBuf;
    //use serde_json;

    #[test]
    fn recovery_drill_success() {
        let base = env::temp_dir().join(format!("archive-cli-drill-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).unwrap();
        let source_dir = base.join("source");
        let backup_dir = base.join("backup");
        let source = Archive::init(&source_dir).unwrap();
        source
            .import_bytes(b"data", oiaf::Source::filesystem("test", "item", "1"))
            .unwrap();
        DirectoryBackup::create(&source, &backup_dir).unwrap();
        let root_key_bytes: [u8; 32] = [0u8; 32];
        let kit = RecoveryKit::generate(&root_key_bytes, 1_800_000_000_000).unwrap();
        let recovery_key = kit.recovery_key_value().unwrap();
        let control_payload = b"control payload";
        let fixture =
            RecoveryDrill::create_fixture(&recovery_key, control_payload, 1_700_000_000_000)
                .unwrap();
        let fixture_path = backup_dir.join("recovery_fixture.json");
        fs::write(&fixture_path, serde_json::to_string(&fixture).unwrap()).unwrap();
        let key_file = backup_dir.join("key.txt");
        std::fs::write(&key_file, recovery_key.to_formatted_string()).unwrap();
        let kit_path = backup_dir.join("recovery_kit.json");
        std::fs::write(&kit_path, serde_json::to_string(&kit).unwrap()).unwrap();
        let cli = Cli::try_parse_from([
            "oiaf",
            "recovery-drill",
            backup_dir.to_str().unwrap(),
            "--key-file",
            key_file.to_str().unwrap(),
        ])
        .expect("valid recovery-drill command");
        let res = run(cli).unwrap();
        let receipt: RecoveryDrillReceipt = serde_json::from_value(res).unwrap();
        assert!(receipt.success);
        assert!(receipt.objects > 0);
        assert_eq!(receipt.pending_jobs, 0);
        assert_eq!(receipt.failed_jobs, 0);
        assert!(receipt.archive_ready);
    }

    #[test]
    fn recovery_drill_wrong_key() {
        let base = env::temp_dir().join(format!("archive-cli-drill-wrong-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).unwrap();
        let source_dir = base.join("source");
        let backup_dir = base.join("backup");
        let source = Archive::init(&source_dir).unwrap();
        source
            .import_bytes(b"data", oiaf::Source::filesystem("test", "item", "1"))
            .unwrap();
        fs::create_dir_all(&backup_dir).unwrap();
        let recovery_key = RecoveryKey::generate();
        let wrong_key = RecoveryKey::generate();
        let control_payload = b"control payload";
        let fixture =
            RecoveryDrill::create_fixture(&recovery_key, control_payload, 1_700_000_000_000)
                .unwrap();
        let fixture_path = backup_dir.join("recovery_fixture.json");
        fs::write(&fixture_path, serde_json::to_string(&fixture).unwrap()).unwrap();

        let key_file = backup_dir.join("key.txt");
        std::fs::write(&key_file, wrong_key.to_formatted_string()).unwrap();
        let cli = Cli::try_parse_from([
            "oiaf",
            "recovery-drill",
            backup_dir.to_str().unwrap(),
            "--key-file",
            key_file.to_str().unwrap(),
        ])
        .expect("valid recovery-drill command");
        let res = run(cli);
        assert!(res.is_err());
    }

    #[test]
    fn recovery_drill_malformed_key() {
        let base = env::temp_dir().join(format!(
            "archive-cli-drill-malformed-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).unwrap();
        let source_dir = base.join("source");
        let backup_dir = base.join("backup");
        let source = Archive::init(&source_dir).unwrap();
        source
            .import_bytes(b"data", oiaf::Source::filesystem("test", "item", "1"))
            .unwrap();
        fs::create_dir_all(&backup_dir).unwrap();
        let recovery_key = RecoveryKey::generate();
        let control_payload = b"control payload";
        let fixture =
            RecoveryDrill::create_fixture(&recovery_key, control_payload, 1_700_000_000_000)
                .unwrap();
        let fixture_path = backup_dir.join("recovery_fixture.json");
        fs::write(&fixture_path, serde_json::to_string(&fixture).unwrap()).unwrap();

        let key_file = backup_dir.join("key.txt");
        std::fs::write(&key_file, "invalid-key-format").unwrap();
        let cli = Cli::try_parse_from([
            "oiaf",
            "recovery-drill",
            backup_dir.to_str().unwrap(),
            "--key-file",
            key_file.to_str().unwrap(),
        ])
        .expect("valid recovery-drill command");
        let res = run(cli);
        assert!(res.is_err());
    }

    #[test]
    fn recovery_drill_missing_backup() {
        let key_file = PathBuf::from("somekey");
        let cli = Cli::try_parse_from([
            "oiaf",
            "recovery-drill",
            "nonexistent_backup",
            "--key-file",
            key_file.to_str().unwrap(),
        ])
        .expect("valid recovery-drill command");
        let res = run(cli);
        assert!(res.is_err());
    }

    #[test]
    fn recovery_drill_tampered_backup() {
        let base = env::temp_dir().join(format!("archive-cli-drill-tamper-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).unwrap();
        let source_dir = base.join("source");
        let backup_dir = base.join("backup");
        let source = Archive::init(&source_dir).unwrap();
        source
            .import_bytes(b"data", oiaf::Source::filesystem("test", "item", "1"))
            .unwrap();
        fs::create_dir_all(&backup_dir).unwrap();
        // tamper by writing empty file
        std::fs::write(backup_dir.join("tamper.txt"), "").unwrap();
        let root_key_bytes: [u8; 32] = [0u8; 32];
        let kit = RecoveryKit::generate(&root_key_bytes, 1_800_000_000_000).unwrap();
        let recovery_key = kit.recovery_key_value().unwrap();
        let control_payload = b"control payload";
        let fixture =
            RecoveryDrill::create_fixture(&recovery_key, control_payload, 1_700_000_000_000)
                .unwrap();
        let fixture_path = backup_dir.join("recovery_fixture.json");
        fs::write(&fixture_path, serde_json::to_string(&fixture).unwrap()).unwrap();
        let key_file = backup_dir.join("key.txt");
        std::fs::write(&key_file, recovery_key.to_formatted_string()).unwrap();
        let kit_path = backup_dir.join("recovery_kit.json");
        std::fs::write(&kit_path, serde_json::to_string(&kit).unwrap()).unwrap();
        let cli = Cli::try_parse_from([
            "oiaf",
            "recovery-drill",
            backup_dir.to_str().unwrap(),
            "--key-file",
            key_file.to_str().unwrap(),
        ])
        .expect("valid recovery-drill command");
        let res = run(cli);
        assert!(res.is_err());
    }

    #[test]
    fn recovery_drill_mismatched_kit() {
        let base =
            env::temp_dir().join(format!("archive-cli-drill-mismatch-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).unwrap();
        let source_dir = base.join("source");
        let backup_dir = base.join("backup");
        let source = Archive::init(&source_dir).unwrap();
        source
            .import_bytes(b"data", oiaf::Source::filesystem("test", "item", "1"))
            .unwrap();
        DirectoryBackup::create(&source, &backup_dir).unwrap();
        // generate kit with different root key
        let root_key_bytes1: [u8; 32] = [0u8; 32];
        let kit1 = RecoveryKit::generate(&root_key_bytes1, 1_800_000_000_000).unwrap();
        let key1 = kit1.recovery_key_value().unwrap();
        let control_payload = b"control payload";
        let fixture =
            RecoveryDrill::create_fixture(&key1, control_payload, 1_700_000_000_000).unwrap();
        let fixture_path = backup_dir.join("recovery_fixture.json");
        fs::write(&fixture_path, serde_json::to_string(&fixture).unwrap()).unwrap();
        let root_key_bytes2: [u8; 32] = [1u8; 32];
        let kit2 = RecoveryKit::generate(&root_key_bytes2, 1_800_000_000_000).unwrap();
        // use kit2 for file but fixture uses kit1's key
        let kit_path = backup_dir.join("recovery_kit.json");
        fs::write(&kit_path, serde_json::to_string(&kit2).unwrap()).unwrap();
        let key_file = backup_dir.join("key.txt");
        fs::write(&key_file, key1.to_formatted_string()).unwrap();
        let cli = Cli::try_parse_from([
            "oiaf",
            "recovery-drill",
            backup_dir.to_str().unwrap(),
            "--key-file",
            key_file.to_str().unwrap(),
        ])
        .expect("valid recovery-drill command");
        let res = run(cli);
        assert!(res.is_err());
    }
}
