//! Bounded newline-delimited MCP stdio. Stdout contains protocol messages only.
//! Tools never apply, register, delete, overwrite, resolve, or run shell commands.
//! Transport/version contract: https://modelcontextprotocol.io/specification/2024-11-05/basic/transports
use serde_json::{json, Value};
use std::io::{self, BufRead, Write};
use std::path::Path;

pub const MAX_MESSAGE_BYTES: usize = 256 * 1024;
pub const PROTOCOL_VERSION: &str = "2024-11-05";

fn error(id: Value, code: i64, message: &str) -> Value {
    json!({"jsonrpc":"2.0", "id":id, "error":{"code":code,"message":message}})
}

pub fn tools() -> Value {
    let description = [
        ("workspace_status", "Read durable pair IDs and plan states; no local paths or file text.", None),
        ("sync_preview", "Reconcile registered roots and record a dry-run plan; never apply. Writes local plan metadata and eligible content objects.", Some("pair_id")),
        ("event_log", "Read event IDs, operation kinds and receipt states without paths or file text.", None),
        ("agent_handoff", "Scan and return redacted workspace evidence. May populate local object-cache metadata; never modify workspace files or start an agent.", Some("pair_id")),
    ];
    Value::Array(description.into_iter().map(|(name, description, argument)| {
        let properties = match argument {
            Some(key) => json!({(key):{"type":"string","minLength":1,"maxLength":128}}),
            None => json!({}),
        };
        let required: Vec<&str> = argument.into_iter().collect();
        json!({"name":name,"description":description,
            "inputSchema":{"type":"object","properties":properties,"required":required,"additionalProperties":false},
            "annotations":{"readOnlyHint":name!="sync_preview","destructiveHint":false,"idempotentHint":name!="sync_preview","openWorldHint":false}})
    }).collect())
}

/// Drop roots, names, relative paths, scan-map keys and future fields until reviewed.
fn agent_view(value: &Value) -> Value {
    match value {
        Value::Array(items) => Value::Array(items.iter().map(agent_view).collect()),
        Value::Object(map) => {
            let mut safe = serde_json::Map::new();
            for (key, value) in map {
                if matches!(
                    key.as_str(),
                    "id" | "pair_id"
                        | "plan_id"
                        | "state"
                        | "kind"
                        | "side"
                        | "before"
                        | "after"
                        | "sequence"
                        | "seq"
                        | "revision"
                        | "source_files"
                        | "target_files"
                        | "workspace_creation_allowed"
                        | "timestamp"
                        | "mutated_files"
                        | "blocked"
                        | "ready"
                ) {
                    safe.insert(key.clone(), value.clone());
                } else if matches!(
                    key.as_str(),
                    "pairs" | "plans" | "events" | "operations" | "pending" | "evidence"
                ) {
                    safe.insert(key.clone(), agent_view(value));
                } else if matches!(
                    key.as_str(),
                    "blockers" | "conflicts" | "changed" | "source_scan" | "target_scan"
                ) {
                    let count = value
                        .as_array()
                        .map(Vec::len)
                        .or_else(|| value.as_object().map(serde_json::Map::len))
                        .or_else(|| value.as_u64().map(|count| count as usize))
                        .unwrap_or(0);
                    safe.insert(format!("{key}_count"), json!(count));
                }
            }
            Value::Object(safe)
        }
        _ => Value::Null,
    }
}

pub struct Server<F> {
    initialized: bool,
    runtime: F,
}

impl<F: FnMut(Value) -> Result<Value, String>> Server<F> {
    pub fn new(runtime: F) -> Self {
        Self {
            initialized: false,
            runtime,
        }
    }

    pub fn handle(&mut self, request: Value) -> Option<Value> {
        let id = request.get("id").cloned();
        let method = request.get("method").and_then(Value::as_str);
        if request.get("jsonrpc") != Some(&json!("2.0"))
            || method.is_none()
            || id
                .as_ref()
                .is_some_and(|v| !v.is_string() && !v.is_number() && !v.is_null())
        {
            return Some(error(Value::Null, -32600, "Invalid Request"));
        }
        let method = method.unwrap();
        let Some(id) = id else {
            return None;
        };
        let params = request.get("params").cloned().unwrap_or_else(|| json!({}));
        if !params.is_object() {
            return Some(error(id, -32602, "Invalid params"));
        }
        let result = match method {
            "initialize" => {
                if params
                    .get("protocolVersion")
                    .and_then(Value::as_str)
                    .is_none()
                    || !params.get("capabilities").is_some_and(Value::is_object)
                    || !params.get("clientInfo").is_some_and(Value::is_object)
                {
                    return Some(error(
                        id,
                        -32602,
                        "Initialization requires protocolVersion, capabilities and clientInfo",
                    ));
                }
                self.initialized = true;
                json!({"protocolVersion":PROTOCOL_VERSION,"capabilities":{"tools":{"listChanged":false}},
                    "serverInfo":{"name":"devdrop-local","version":env!("CARGO_PKG_VERSION")},
                    "instructions":"Local evidence only. Preview records metadata and eligible objects; no tool applies sync. Paths, file text and env values are omitted. Review and approve plans in the desktop or CLI."})
            }
            "ping" => json!({}),
            _ if !self.initialized => {
                return Some(error(id, -32002, "Initialize the server first"))
            }
            "tools/list" => json!({"tools":tools()}),
            "tools/call" => {
                let Some(name) = params.get("name").and_then(Value::as_str) else {
                    return Some(error(id, -32602, "Tool name is required"));
                };
                let arguments = params
                    .get("arguments")
                    .cloned()
                    .unwrap_or_else(|| json!({}));
                let Some(arguments) = arguments.as_object() else {
                    return Some(error(id, -32602, "Tool arguments must be an object"));
                };
                let (action, needs_pair) = match name {
                    "workspace_status" => ("list", false),
                    "sync_preview" => ("preview", true),
                    "event_log" => ("events", false),
                    "agent_handoff" => ("handoff", true),
                    _ => return Some(error(id, -32602, "Unknown tool")),
                };
                if arguments.keys().any(|key| !needs_pair || key != "pair_id") {
                    return Some(error(id, -32602, "Unexpected tool argument"));
                }
                let mut runtime_request = json!({"action":action});
                if needs_pair {
                    let Some(pair_id) = arguments.get("pair_id").and_then(Value::as_str) else {
                        return Some(error(id, -32602, "pair_id is required"));
                    };
                    if pair_id.is_empty()
                        || pair_id.len() > 128
                        || !pair_id
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b':'))
                    {
                        return Some(error(id, -32602, "Invalid pair identifier"));
                    }
                    runtime_request["pair_id"] = json!(pair_id);
                }
                match (self.runtime)(runtime_request) {
                    Ok(value) => {
                        let evidence = json!({"evidence":agent_view(&value), "workspace_files_mutated":false,
                            "local_metadata_may_change":true,"object_cache_may_change":needs_pair,"beta_warning":devdrop_core::local::BETA_WARNING});
                        json!({"content":[{"type":"text","text":serde_json::to_string(&evidence).expect("metadata serializes")}],"isError":false})
                    }
                    Err(_) => {
                        json!({"content":[{"type":"text","text":"Local operation refused. Inspect the desktop or CLI for recovery guidance."}],"isError":true})
                    }
                }
            }
            _ => return Some(error(id, -32601, "Method not found")),
        };
        Some(json!({"jsonrpc":"2.0","id":id,"result":result}))
    }
}

/// Bound single-line allocation while retaining stream recovery after invalid input.
pub fn serve_with<R: BufRead, W: Write, F: FnMut(Value) -> Result<Value, String>>(
    mut input: R,
    mut output: W,
    runtime: F,
) -> io::Result<()> {
    let mut server = Server::new(runtime);
    loop {
        let mut line = Vec::new();
        let mut oversized = false;
        loop {
            let buffer = input.fill_buf()?;
            if buffer.is_empty() {
                break;
            }
            let end = buffer.iter().position(|b| *b == b'\n').map(|p| p + 1);
            let consumed = end.unwrap_or(buffer.len());
            if line.len() + consumed > MAX_MESSAGE_BYTES {
                oversized = true;
            }
            if !oversized {
                line.extend_from_slice(&buffer[..consumed]);
            }
            input.consume(consumed);
            if end.is_some() {
                break;
            }
        }
        if line.is_empty() && !oversized {
            break;
        }
        let response = if oversized {
            Some(error(
                Value::Null,
                -32700,
                "Message exceeds transport limit",
            ))
        } else {
            match serde_json::from_slice(&line) {
                Ok(request) => server.handle(request),
                Err(_) => Some(error(Value::Null, -32700, "Parse error")),
            }
        };
        if let Some(response) = response {
            serde_json::to_writer(&mut output, &response)?;
            output.write_all(b"\n")?;
            output.flush()?;
        }
    }
    Ok(())
}

pub fn serve(state_dir: &Path) -> io::Result<()> {
    serve_with(io::stdin().lock(), io::stdout().lock(), |request| {
        devdrop_core::local::dispatch(state_dir, request)
            .map_err(|_| "Local operation refused".to_owned())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn init() -> Value {
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":PROTOCOL_VERSION,"capabilities":{},"clientInfo":{"name":"test","version":"1"}}})
    }

    #[test]
    fn initialization_listing_calls_and_notifications() {
        let mut server = Server::new(|_| {
            Ok(
                json!({"pairs":[{"id":"pair:1","source":"/private/source","target":"/private/target","name":"private"}],"secret":"DO_NOT_LEAK","file_contents":"DO_NOT_LEAK"}),
            )
        });
        assert_eq!(
            server
                .handle(json!({"jsonrpc":"2.0","id":0,"method":"tools/list"}))
                .unwrap()["error"]["code"],
            -32002
        );
        assert_eq!(
            server.handle(init()).unwrap()["result"]["protocolVersion"],
            PROTOCOL_VERSION
        );
        assert!(server
            .handle(json!({"jsonrpc":"2.0","method":"notifications/initialized"}))
            .is_none());
        let listed = server
            .handle(json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}))
            .unwrap();
        assert_eq!(listed["result"]["tools"].as_array().unwrap().len(), 4);
        let reply=server.handle(json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"workspace_status","arguments":{}}})).unwrap();
        let text = reply.to_string();
        let evidence: Value =
            serde_json::from_str(reply["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
        assert_eq!(evidence["beta_warning"], devdrop_core::local::BETA_WARNING);
        assert!(text.contains("pair:1"));
        for forbidden in ["DO_NOT_LEAK", "/private/", "file_contents", "private"] {
            assert!(!text.contains(forbidden));
        }
    }

    #[test]
    fn no_apply_shell_arbitrary_paths_or_error_echo() {
        let mut server = Server::new(|_| Err("DO_NOT_LEAK /private/root".to_owned()));
        server.handle(init());
        for params in [
            json!({"name":"apply","arguments":{}}),
            json!({"name":"sync_preview","arguments":{"pair_id":"../../outside"}}),
            json!({"name":"workspace_status","arguments":{"shell":"DO_NOT_LEAK"}}),
        ] {
            let value = server
                .handle(json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":params}))
                .unwrap();
            assert!(value.get("error").is_some());
            assert!(!value.to_string().contains("DO_NOT_LEAK"));
        }
        let value=server.handle(json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"sync_preview","arguments":{"pair_id":"pair:1"}}})).unwrap();
        assert_eq!(value["result"]["isError"], true);
        assert!(!value.to_string().contains("/private/"));
    }

    #[test]
    fn streamed_messages_parse_failure_and_oversize_recover() {
        let mut input = Vec::new();
        input.extend_from_slice(b"invalid\n");
        input.extend_from_slice(&vec![b'x'; MAX_MESSAGE_BYTES + 1]);
        input.push(b'\n');
        input.extend_from_slice(serde_json::to_string(&init()).unwrap().as_bytes());
        input.push(b'\n');
        input
            .extend_from_slice(b"{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n");
        input.extend_from_slice(b"{\"jsonrpc\":\"2.0\",\"id\":5,\"method\":\"ping\"}\n");
        let mut output = Vec::new();
        serve_with(io::Cursor::new(input), &mut output, |_| Ok(json!({}))).unwrap();
        let messages: Vec<Value> = String::from_utf8(output)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(messages.len(), 4);
        assert_eq!(messages[0]["error"]["code"], -32700);
        assert_eq!(messages[1]["error"]["code"], -32700);
        assert_eq!(messages[2]["id"], 1);
        assert_eq!(messages[3]["id"], 5);
    }
}
