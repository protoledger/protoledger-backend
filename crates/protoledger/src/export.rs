//! `protoledger export` — описание протокола в виде диссектора Wireshark.

use std::path::PathBuf;

use clap::Args;
use pl_interp::Interpretation;

use crate::common::{Exit, read_text};

#[derive(Args)]
pub struct ExportArgs {
    /// Файл интерпретации (YAML, protoledger/interpretation@1)
    #[arg(long)]
    pub interpretation: PathBuf,
    /// Имя протокола в Wireshark: строчные латинские буквы, цифры, подчёркивания
    #[arg(long)]
    pub name: String,
    /// Куда записать диссектор (.lua); без значения — в стандартный вывод
    #[arg(long)]
    pub out: Option<PathBuf>,
}

pub fn run(args: ExportArgs) -> Result<Exit, String> {
    let text = read_text(&args.interpretation)?;
    let it = Interpretation::parse(&text)
        .map_err(|e| format!("{}: {e}", args.interpretation.display()))?;
    let lua = pl_interp::export::wireshark_lua(&it, &args.name).map_err(|e| e.to_string())?;
    match &args.out {
        Some(path) => {
            std::fs::write(path, &lua).map_err(|e| format!("{}: {e}", path.display()))?;
            eprintln!(
                "Диссектор записан: {}. Проверить: tshark -X lua_script:{} -r <запись> -Y {}",
                path.display(),
                path.display(),
                args.name
            );
        }
        None => print!("{lua}"),
    }
    Ok(Exit::Ok)
}
