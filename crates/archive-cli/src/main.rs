use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand};
use serde::Serialize;

mod adapter;

use adapter::{ArchiveAdapter, OiafAdapter};

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
}

#[derive(Debug, Args)]
struct ArchivePath {
    #[arg(value_name = "ARCHIVE")]
    archive: PathBuf,
}

#[derive(Debug, Args)]
struct ImportArgs {
    #[arg(value_name = "ARCHIVE")]
    archive: PathBuf,
    #[arg(value_name = "SOURCE")]
    source: PathBuf,
}

#[derive(Debug, Args)]
struct VerifyArgs {
    #[arg(value_name = "ARCHIVE")]
    archive: PathBuf,
    #[arg(long, default_value_t = false)]
    full: bool,
}

#[derive(Debug, Args)]
struct ExportArgs {
    #[arg(value_name = "ARCHIVE")]
    archive: PathBuf,
    #[arg(value_name = "DESTINATION")]
    destination: PathBuf,
    #[arg(long, value_name = "OBJECT_ID")]
    object_id: Option<String>,
}

#[derive(Debug, Args)]
struct ProvenanceArgs {
    #[arg(value_name = "ARCHIVE")]
    archive: PathBuf,
    #[arg(value_name = "OBJECT_ID")]
    object_id: String,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<(), CliError> {
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
        Command::Provenance(args) => {
            let archive = OiafAdapter::open(&args.archive)?;
            archive.provenance(&args.object_id)?
        }
    };

    if cli.json {
        print_json(&result)?;
    } else {
        print_text(&result)?;
    }

    Ok(())
}

fn print_json<T: Serialize>(value: &T) -> Result<(), CliError> {
    let output = serde_json::to_string(value).map_err(CliError::Output)?;
    println!("{output}");
    Ok(())
}

fn print_text<T: Serialize>(value: &T) -> Result<(), CliError> {
    let value = serde_json::to_value(value).map_err(CliError::Output)?;
    match value {
        serde_json::Value::Object(object) => {
            for (key, value) in object {
                println!("{key}: {}", display_value(&value));
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                println!("{}", display_value(&item));
            }
        }
        value => println!("{}", display_value(&value)),
    }
    Ok(())
}

fn display_value(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(value) => value.clone(),
        value => value.to_string(),
    }
}

#[derive(Debug)]
enum CliError {
    Adapter(adapter::AdapterError),
    Output(serde_json::Error),
}

impl std::fmt::Display for CliError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Adapter(error) => error.fmt(formatter),
            Self::Output(error) => write!(formatter, "could not encode output: {error}"),
        }
    }
}

impl std::error::Error for CliError {}

impl From<adapter::AdapterError> for CliError {
    fn from(error: adapter::AdapterError) -> Self {
        Self::Adapter(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn parses_import_command() {
        let cli = Cli::try_parse_from(["oiaf", "import", "archive", "photo.jpg"])
            .expect("valid import command");

        assert!(matches!(
            cli.command,
            Command::Import(ImportArgs { archive, source })
                if archive == std::path::Path::new("archive")
                    && source == std::path::Path::new("photo.jpg")
        ));
    }

    #[test]
    fn parses_full_verify_command() {
        let cli = Cli::try_parse_from(["oiaf", "verify", "archive", "--full"])
            .expect("valid verify command");

        assert!(matches!(
            cli.command,
            Command::Verify(VerifyArgs { archive, full })
                if archive == std::path::Path::new("archive") && full
        ));
    }

    #[test]
    fn json_output_is_single_line() {
        let value = serde_json::json!({ "status": "ok", "count": 1 });
        let encoded = serde_json::to_string(&value).expect("serializable JSON");

        assert!(!encoded.contains('\n'));
        assert_eq!(encoded, r#"{"count":1,"status":"ok"}"#);
    }
}
