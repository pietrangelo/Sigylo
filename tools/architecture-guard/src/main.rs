use std::path::PathBuf;
use std::process::ExitCode;

fn main() -> ExitCode {
    let root = std::env::args().nth(1).map(PathBuf::from).unwrap_or_else(|| PathBuf::from("."));
    match architecture_guard::check_workspace(&root) {
        Ok(violations) if violations.is_empty() => {
            println!("architecture guard: the rosette is intact");
            ExitCode::SUCCESS
        }
        Ok(violations) => {
            for v in &violations {
                eprintln!("{v}");
            }
            eprintln!("architecture guard: {} violation(s)", violations.len());
            ExitCode::FAILURE
        }
        Err(e) => {
            eprintln!("architecture guard: {e}");
            ExitCode::from(2)
        }
    }
}
