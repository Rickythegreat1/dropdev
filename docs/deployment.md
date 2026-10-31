# Deployment and release

DevDrop has two delivery surfaces. The native desktop app and Rust command-line
tools run on the developer's machine. The browser app is a disposable-data demo
and operating guide. Hosting the browser app does not host or connect the local
filesystem engine. The observer daemon must remain on loopback; do not expose it
through a public reverse proxy or add unauthenticated write endpoints.

## Build and verification

```sh
cargo fmt --all --check
cargo test --workspace --locked
cargo check --workspace --all-targets --locked
pnpm install --frozen-lockfile
pnpm typecheck
pnpm test
pnpm --filter @devdrop/desktop build
cargo check --manifest-path apps/desktop/src-tauri/Cargo.toml --locked
```

The native check needs the Tauri platform dependencies. On Ubuntu 22.04 these
include `libwebkit2gtk-4.1-dev`, `libayatana-appindicator3-dev`, `librsvg2-dev`,
and `patchelf`. No Docker runtime is required.

`.github/workflows/ci.yml` runs these gates for pull requests and main pushes.
The generated browser artifact is not an installer and cannot perform local
sync. A green workflow records verification of its specific commit; creating
this workflow does not establish that it has run.

## Desktop and command-line artifacts

Run the **Package DevDrop draft** workflow manually on the reviewed branch. It
tests and builds Linux, Windows, and macOS installers plus the CLI, observer
daemon, and read-only MCP executable. Each artifact includes SHA-256 checksums.
The default run uploads workflow artifacts only. The separate manual **Create unpublished DevDrop draft** workflow creates an
unpublished draft for the package version after its packaging job succeeds. It never publishes or approves a release.

Before publishing a draft, verify installer startup and the disposable-two-folder
workflow on each target operating system. Installers are unsigned until the
owner separately configures approved signing identities. Signing credentials,
notarization, paid hosting, and automatic updater credentials are not created by
the build workflow.

## Browser hosting

Build `apps/desktop/dist/` and host it as static assets over HTTPS. Its demo data
must remain clearly labeled as browser-only sample data. It must not upload
project folders, secrets, local SQLite metadata, content-store bytes, or machine
paths. Do not turn a successful static deployment into a claim that network sync
is running.

Create a portable browser artifact after building:

```sh
python scripts/package-browser.py --output /tmp/devdrop-browser-demo.zip
```

The packager accepts compiled web assets only, rejects symlinks and unexpected
file types, and includes asset checksums plus a browser-only scope notice. This
ZIP is a portable static-host artifact; Sites publication uses its own supported
archive format and workflow.

For Sites, use a separate checkout and persist the server-returned opaque project
ID in `.openai/hosting.json`. New Sites remain owner-private. Push the exact
source, package the static output, save the matching source commit, and deploy
the saved version using the owner-private publishing operation. Keep source
credentials in memory, never in this repository, command arguments, or archives.

## Execution record

At preparation time the public DevDrop repository cloned successfully into
`/workspace/dropdev`. The GitHub CLI cannot reach `api.github.com` under the
enforced network policy (`Forbidden`); its authentication-status output therefore
does not establish usable API credentials. Remote workflow runs, a draft pull
request, and release publication have not been verified through that CLI. Use
the supported GitHub connector for authorized repository writes. The Sites
workflow helper scripts are not installed in this executor.

The tested production browser build was copied to the separate
`/workspace/devdrop-host/dist` checkout, and a portable artifact was created at
`/tmp/devdrop-browser-demo.zip`. The archive includes its own asset checksum manifest.
The archive's three compiled assets and checksum manifest were verified.

One owner-private Site was created and its identity persisted atomically at
`/workspace/devdrop-host/.openai/hosting.json`:
`appgprj_6ae6574f8b948191bd7acb0f16a01fdf`. It remains **unpublished**;
`current_live_url` is null and the latest saved version is zero. Its reserved
origin is `https://devdrop-workspace-control.rickymsanderson.chatgpt.site`.
This is not a verified live deployment URL.

Source push and publication are blocked because Sites returned
`http_extra_header` authentication, while its required `site-workflow.mjs`
helper is unavailable. The helper was searched for throughout the executor and
was unavailable through the skill resource reader. No credential was printed,
written to disk, added to a Git remote, or put in the artifact. Resume the same
Site with the supported helper installed, refresh its short-lived credential if
needed, push the exact source, save the matching version, and publish privately.
Do not create another Site or treat the reserved origin as deployment success.

## Native build attempt in this executor

The native lockfile was regenerated for the new core dependencies.
`cargo check --manifest-path apps/desktop/src-tauri/Cargo.toml --locked` then
failed at `glib-sys`: pkg-config could not find `glib-2.0 >= 2.70` (GTK/WebKit
and AppIndicator development libraries are also absent).

The documented official installation was attempted:
`apt-get update && apt-get install -y libwebkit2gtk-4.1-dev libayatana-appindicator3-dev librsvg2-dev patchelf`.
The executor runs as uid 1000, has no `sudo`, and the attempt with sandbox
escalation still failed reading apt configuration and creating
`/var/lib/apt/lists/partial` (`Permission denied`). No packages were installed.
Linux Tauri compilation/installer output is blocked on an environment with
those official packages or an authorized privileged package installer. Windows
and macOS packaging have not been run here.

## Source publication and review

The tested source branch is `codex/local-sync-mvp-20261031` in the public
`Rickythegreat1/dropdev` repository. Git push succeeded using the existing
repository access. Creating the draft PR through the GitHub connector was
**denied by automatic approval review**, which stated that explicit user
permission is required for that external publication action. The PR was not
created and the denied operation was not retried through another route.
The parent must resolve that approval before opening the PR.

CI also runs for the `codex/**` review branches. On public-repository pushes it
calls the artifact-only platform packaging workflow, so
Windows/macOS/Linux binaries can be verified without publishing or approving a
release. No paid runner or signing credential is configured. Read the actual
workflow result before describing any OS artifact as passed.

The first review-branch Actions run failed workflow validation before executing
jobs because a skipped draft-release job still requested write permissions from
a read-only reusable-workflow caller. Draft publication was split into its own
manual workflow; the reused packaging workflow now requests read-only access.
The initial failed run is `41242515367`; follow the latest branch run for checks.

The next platform run exposed a pre-existing package-manager mismatch:
`pnpm-workspace.yaml` uses workspace overrides understood by pnpm 11, while
package.json declared pnpm 9. The declared manager is now pinned to the tested
pnpm 11.19.0, so frozen installs consume the same override configuration as the
local build. Do not treat the earlier pnpm-install failures as OS build results.

Platform tests also account for Git LFS filters preconfigured on hosted runners:
a nested-worktree refusal due to external filters is accepted as a fail-closed
result, without executing those filters. Disposable fixture roots use their
canonical temporary-directory paths so macOS `/var` aliases do not conflict with
the runtime's deliberate symlink-path refusal.
