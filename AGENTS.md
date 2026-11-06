# AgentProof project rules

- Use Python 3 standard library only for the MVP.
- Keep all checks local-first; never upload project contents.
- Sensitive paths are metadata-only by default: do not hash or copy their contents.
- Verification commands must be explicitly listed in configuration; never infer and execute arbitrary commands.
- Restore is preview-only unless the caller passes `--yes`; never delete files that were added after a snapshot.
- A PASS requires command checks, artifact checks, and sensitive-change checks to pass.

