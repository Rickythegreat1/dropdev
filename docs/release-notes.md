# DevDrop local MVP

This release candidate separates the local Rust sync engine and desktop app from
the hosted browser demo. The browser demo operates on generated sample data and
cannot access or synchronize local project folders.

The local workflow registers a source and target folder, records durable state,
previews file operations, and requires approval of a specific plan before apply.
Conflicts, stale previews, and unsafe paths block apply. Inspect the receipt and
recovery instructions before continuing work after an interrupted operation.

Installers in this draft are unsigned release candidates. Review CI and test on
disposable project copies before publishing a release. Code signing, operating
system trust prompts, and clean-machine installation validation require a
separate release review. No automatic updater or public write service is enabled.
