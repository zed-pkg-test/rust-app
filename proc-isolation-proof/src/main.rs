//! CLI entrypoint.

fn main() {
    let exit_code =
        match ores_proc_isolation::flags::parse().and_then(ores_proc_isolation::runner::run) {
            Ok(code) => code,
            Err(error) => {
                eprintln!("ores-proc-isolation: {error}");
                match error {
                    ores_proc_isolation::Error::Cli(_)
                    | ores_proc_isolation::Error::PolicyRead { .. }
                    | ores_proc_isolation::Error::PolicyInvalid { .. }
                    | ores_proc_isolation::Error::Resolution(_)
                    | ores_proc_isolation::Error::Executable(_) => 2,
                    _ => 125,
                }
            }
        };
    std::process::exit(exit_code);
}
