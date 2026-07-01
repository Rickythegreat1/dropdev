use devdrop_mcp::{dispatch, mcp_tool_schemas, McpToolRequest};
use std::io::{self, Read};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let list_tools = std::env::args().any(|arg| arg == "--list-tools");

    if list_tools {
        println!("{}", serde_json::to_string_pretty(&mcp_tool_schemas())?);
        return Ok(());
    }

    let mut input = String::new();
    io::stdin().read_to_string(&mut input)?;

    if input.trim().is_empty() {
        println!("{}", serde_json::to_string_pretty(&mcp_tool_schemas())?);
        return Ok(());
    }

    let request: McpToolRequest = serde_json::from_str(&input)?;
    let response = dispatch(request);
    println!("{}", serde_json::to_string_pretty(&response)?);

    Ok(())
}
