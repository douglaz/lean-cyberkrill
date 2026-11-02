# AGENTS.md

Lean 4 port of [cyberkrill](https://github.com/douglaz/cyberkrill) as reusable Bitcoin, Lightning and
Fedimint libraries plus the CLI. `plan.md` is the source of truth for scope, decisions and phase
definitions of done; the beads tracker (`br`) holds the executable work.

## Layout and commands

- Seven Lake packages under `packages/` (see `README.md`), one flake, one toolchain (Lean v4.35.0,
  official release packaged in `flake.nix`). Every lakefile is `lakefile.lean`.
- Per package: `cd packages/<pkg> && nix develop -c lake build && nix develop -c lake test`.
- Whole repo: `nix flake check` builds and tests every package in the nix sandbox, then runs the
  app. A new package must be added to `lakePackages` in `flake.nix`, or the check skips it.
  - One exception (owner decision, 2026-10-23; `plan.md` §7 question 3): the two Phase 11 packages
    that depend on Mathlib, the btc-verified bridge and the 11b btc-verified oracle, stay out of
    `lakePackages`. A second CI job on every PR fetches Mathlib's prebuilt files
    (`lake exe cache get`), then builds and tests only those two, with the no-`sorry` check, the
    axiom gate and the 11b suite. "CI green" means both jobs pass. The job lands with Phase 11;
    no other package may leave `lakePackages`.
- Packages depend on each other by path (`require bitcoin from ".." / "bitcoin"`). Commit each
  package's `lake-manifest.json`.

## Rules for this codebase

- **Reference only.** cyberkrill @ `27cad1f` is read, never modified. Golden outputs and derived
  expectations come from
  `nix build --no-link github:douglaz/cyberkrill/27cad1faba86260b06665a89f0af5134d23525c2`, or from
  a throwaway clone of that commit in a temp dir built with that commit's own `nix develop`, never
  from a local working checkout. A clone only gains a temporary test that calls the pure functions
  its bead names, never one that opens a connection. Fetch its dependencies first (network allowed
  for that step only), then run the test offline inside `unshare -rn sh -c 'ip link set lo up && …'`
  with `HOME` set to a temp dir. Commit the script and its output. If the clone does not build, use
  the cross-check the bead names and mark the expectation hand-derived in README.
- **Package boundaries.** Pure packages never import `secp256k1` or `http-curl`. Curve operations reach
  pure code as a supplied structure of functions. C code lives only in those two packages. Proofs
  that need Mathlib go in a separate `<pkg>-proofs` package.
- **Proof hygiene.** No `sorry` anywhere. No `native_decide` in library or proof modules (test files
  may use it). `#print axioms` on every theorem a phase lists shows only `propext`,
  `Classical.choice` and `Quot.sound`. Never weaken a theorem the plan states; stop and report.
- **Safety.** Tests use only published vectors, published test mnemonics, the BOLT #11
  specification's published example private key (tests only), recordings from a throwaway regtest
  node, and synthetic or script-generated fixtures under the third-party rule (for example
  cyberkrill's captured outputs on those inputs, synthetic provider responses, our own LNURL and LUD
  JSON, values a committed script derives from published inputs). Never anything from the owner's
  node, wallets or devices. Tests never reach the internet, port 8332 or `~/.bitcoin`. Nothing
  committed contains private keys, seeds, xprvs, tprvs or WIF keys, or real addresses, xpubs or
  device dumps, apart from that BOLT #11 example key. No hardware wallets, no signing outside test
  vectors, no broadcast, no mainnet funds.
- **Licence.** New Lean, C and script files we write start with (third-party and copied files follow
  the rule below; JSON and other formats without comments need none):
  ```
  /-
  Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
  Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
  -/
  ```
  Third-party material:
  - Admitted in the tree, each with a provenance sidecar or header line (source URL, commit, path,
    licence), never the dual-licence header: MIT, BSD, ISC, CC0 or public domain, and CC-BY-4.0
    (attribution and a note of any changes, for example "extracted and reformatted", kept in the
    sidecar). Material offered under a choice that includes MIT (such as fedimint-lite's
    `MIT OR Apache-2.0`) is taken under MIT.
  - Kept out of the tree: Apache-2.0-only, share-alike (CC-BY-SA) and unlicensed material. Use a
    pinned non-flake input read at test time, or replace it with vectors we generate ourselves.
  - Copied code whose upstream file has no header gets a provenance comment (upstream repo, commit,
    path, "MIT") with the upstream MIT notice in a file beside it, never the dual-licence header.
- **Git.** Work on a feature branch; never commit or push to `master`; the owner merges PRs.
  The repo has been public since 2026-10-22 (owner decision). The owner's standing go-ahead covers
  pushing feature branches and opening PRs (plan.md §1 Visibility); nothing else is pushed. A
  work session never pushes; this overrides the `git push` line in the beads Session Protocol
  below. Conventional commits
  (`feat(bitcoin): ...`). Commit messages and PR text describe the change only, with no tool or
  co-author attribution trailers. Never commit machine-local instruction files.
- **Public text.** Committed files, commit messages, bead text and PR text never name the agent or
  automation tooling behind the work, its roles or flags, models, usage quotas, or machine-local
  paths (home directories, specific temp directories). Write a temp directory as a shell variable
  (`"$TMP_ROOT"`; a bare `<tmpdir>` is a redirect in a copied command) and cite a reference
  source by upstream URL and commit, not by a local copy. The committed `.beads/config.yaml` sets
  the neutral `actor` that `br` records as `created_by`; never pass `--actor`. `br` always records
  the workspace's absolute path as `source_repo_path` on create, so clear it right after every
  `br create`: `br update <id> --source-repo-path ""`.

<!-- agent-discipline-v1 -->

## Working agreement

- Verify edits in the resulting diff, including intended additions and removals.
  For scripted replacements, assert the expected matches before writing and use
  literal replacement values.
- Stage only intended changes and inspect the staged diff, including any hunks
  that were already dirty. Check the commit command's exit status and inspect the
  committed content; a clean worktree alone does not prove the change landed.
- Run the complete gate without piping it through an output filter. If capturing
  output, redirect the whole gate to a fresh log, save its status before reading
  the log, and return that status. Use the repository's existing runner when
  timeout or process supervision is needed; keep that machinery out of this file.
- Report the command and observed exit status when claiming work passes, is clean,
  works, is verified or is done.
  Interrupted or incomplete execution is unverified. A clean review is independent
  judgment, not evidence that a build or test ran.
- Support claims about tool behavior with a reproducible command, relevant version
  and mode, and observed result; capture stdout and stderr separately when the
  distinction matters. Label unmeasured claims and distinguish an observed result
  from a cause established by a controlled comparison or documentation.
- For a bug regression test, demonstrate that it catches the bug on unfixed code
  and passes with the fix. Check the failure is the intended assertion, rather
  than setup or an unrelated error. Use a disposable environment for a deliberate
  break that could affect live systems or funds; otherwise report that the red
  run was not performed.

Gate for this repo: `nix flake check`
<!-- end-agent-discipline -->

<!-- br-agent-instructions-v1 -->

---

## Beads Workflow Integration

This project uses [beads_rust](https://github.com/Dicklesworthstone/beads_rust) (`br`/`bd`) for issue tracking. Issues are stored in `.beads/` and tracked in git.

### Essential Commands

```bash
# View ready issues (open, unblocked, not deferred)
br ready              # or: bd ready

# List and search
br list --status=open # All open issues
br show <id>          # Full issue details with dependencies
br search "keyword"   # Full-text search

# Create and update
br create --title="..." --description="..." --type=task --priority=2
br update <id> --status=in_progress
br close <id> --reason="Completed"
br close <id1> <id2>  # Close multiple issues at once

# Sync with git
br sync --flush-only  # Export DB to JSONL
br sync --status      # Check sync status
```

### Workflow Pattern

1. **Start**: Run `br ready` to find actionable work
2. **Claim**: Use `br update <id> --status=in_progress`
3. **Work**: Implement the task
4. **Complete**: Use `br close <id>`
5. **Sync**: Always run `br sync --flush-only` at session end

### Key Concepts

- **Dependencies**: Issues can block other issues. `br ready` shows only open, unblocked work.
- **Priority**: P0=critical, P1=high, P2=medium, P3=low, P4=backlog (use numbers 0-4, not words)
- **Types**: task, bug, feature, epic, chore, docs, question
- **Blocking**: `br dep add <issue> <depends-on>` to add dependencies

### Session Protocol

**Before ending any session, run this checklist:**

```bash
git status              # Check what changed
git add <files>         # Stage code changes
br sync --flush-only    # Export beads changes to JSONL
git commit -m "..."     # Commit everything
git push                # Push to remote
```

### Best Practices

- Check `br ready` at session start to find available work
- Update status as you work (in_progress → closed)
- Create new issues with `br create` when you discover tasks
- Use descriptive titles and set appropriate priority/type
- Always sync before ending session

<!-- end-br-agent-instructions -->
