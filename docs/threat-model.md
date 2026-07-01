# Threat Model

## Assets

- Source code and project metadata.
- Env file presence and key names.
- Secret values that may exist in user files or process environments.
- Git state and uncommitted work.
- Local CAS objects and queue metadata.

## Primary Risks

- Leaking raw env values through CLI, UI, logs, tests, MCP, or handoff JSON.
- Capturing generated files and bloating or corrupting the CAS.
- Treating watcher events as truth and missing reconciliation.
- Deleting or overwriting files without a restore path.
- Asking an agent to work from stale, incomplete, or misleading workspace state.
- Presenting generic UI confidence without evidence.

## Slice 0/1 Controls

- No live sync apply exists.
- No deletion, overwrite, hydration, Git mutation, or database writes exist.
- Hooks are present but inert and not auto-enabled.
- MCP tools are schema stubs with `mutatesFiles=false` and
  `exposesSecretValues=false`.
- Tests cover redaction, ignored paths, dry-run behavior, model serialization,
  and Windows-style path serialization.

