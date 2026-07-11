# Subagent Task

## Objective

<Concrete task outcome.>

## Ownership

- Files/modules owned by this subagent:
  - `<path>`
- Do not modify:
  - `<path or area>`

## Required Reading

- `.codex/skills/centos-feature-dev/SKILL.md`
- `<matching feature skill>`
- `<specific references>`

## Implementation Notes

- Follow legacy Django style and existing local patterns.
- Preserve security invariants and sensitive-field omissions.
- Do not revert unrelated worktree changes.
- If permissions, sandboxing, missing dependencies, or unclear requirements block progress, stop and report the blocker.

## Validation

Run the narrowest useful command(s):

```bash
<command>
```

If validation cannot run, report the exact reason.

## Final Response

Return:

- Files changed
- Behavior changed
- Tests/validation run and result
- Risks, skipped checks, or blockers
