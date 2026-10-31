use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let mut state_dir = None;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--list-tools" => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&devdrop_mcp::protocol::tools())?
                );
                return Ok(());
            }
            "--state-dir" if state_dir.is_none() => {
                state_dir = args.next().map(PathBuf::from);
                if state_dir.is_none() {
                    return Err("--state-dir requires a path".into());
                }
            }
            "--help" | "-h" => {
                eprintln!("devdrop-mcp --state-dir PATH\nLocal MCP over newline-delimited JSON-RPC stdio. No apply tools.\ndevdrop-mcp --list-tools");
                return Ok(());
            }
            _ => return Err("Unknown argument; use --help".into()),
        }
    }
    let state_dir = state_dir
        .ok_or("--state-dir PATH is required; use an existing private DevDrop state directory")?;
    devdrop_mcp::protocol::serve(&state_dir)?;
    Ok(())
}
