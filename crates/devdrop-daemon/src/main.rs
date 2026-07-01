use devdrop_daemon::{run_daemon, DaemonConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    match DaemonConfig::from_args(std::env::args().skip(1))? {
        Some(config) => run_daemon(config).await?,
        None => print_help(),
    }

    Ok(())
}

fn print_help() {
    println!(
        "devdrop-daemon\n\nUSAGE:\n    devdrop-daemon [--bind 127.0.0.1:37431] [--debounce-ms 250] [--scan-budget 10000]\n\nSafety:\n    Observer-only daemon. Loopback bind required. No sync apply, deletion, hydration write, Git mutation, CAS write, or SQLite persistence."
    );
}
