use std::path::PathBuf;

use clap::Parser;

#[derive(Parser)]
#[command(
    name = "pl-hostile",
    about = "Злые записи трафика для проверки устойчивости"
)]
struct Cli {
    /// Каталог результата
    #[arg(long)]
    out: PathBuf,
    /// Дополнительно крупные записи (не для репозитория)
    #[arg(long)]
    large: bool,
}

fn main() -> std::process::ExitCode {
    let cli = Cli::parse();
    if let Err(e) = std::fs::create_dir_all(&cli.out) {
        eprintln!("{e}");
        return std::process::ExitCode::from(2);
    }
    let mut items: Vec<(String, Vec<u8>)> = pl_hostile::samples()
        .into_iter()
        .map(|s| (format!("{}.{}", s.name, s.extension), s.bytes))
        .collect();
    if cli.large {
        for name in pl_hostile::LARGE {
            if let Some(bytes) = pl_hostile::large(name) {
                items.push((format!("{name}.pcap"), bytes));
            }
        }
    }
    for (file, bytes) in items {
        if let Err(e) = std::fs::write(cli.out.join(&file), &bytes) {
            eprintln!("{file}: {e}");
            return std::process::ExitCode::from(2);
        }
        println!("{file}: {} байт", bytes.len());
    }
    std::process::ExitCode::SUCCESS
}
