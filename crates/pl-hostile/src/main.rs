use std::path::PathBuf;

use clap::Parser;

#[derive(Parser)]
#[command(
    name = "pl-hostile",
    about = "Злые записи трафика, журналы, описания и манифесты для проверки устойчивости"
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
    for s in pl_hostile::inputs::journals() {
        items.push((format!("journals/{}.{}", s.name, s.extension), s.bytes));
    }
    for s in pl_hostile::inputs::interpretations() {
        items.push((
            format!("interpretations/{}.{}", s.name, s.extension),
            s.bytes,
        ));
    }
    for s in pl_hostile::inputs::manifests() {
        items.push((format!("projects/{}/project.yaml", s.name), s.bytes));
    }
    for (file, bytes) in items {
        if let Some(parent) = cli.out.join(&file).parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Err(e) = std::fs::write(cli.out.join(&file), &bytes) {
            eprintln!("{file}: {e}");
            return std::process::ExitCode::from(2);
        }
        println!("{file}: {} байт", bytes.len());
    }
    std::process::ExitCode::SUCCESS
}
