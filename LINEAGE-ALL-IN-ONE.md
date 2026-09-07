# `lineage/all-in-one` — integration branch

**Do not open a pull request from this branch against `rossoctl/cortex`.**
It exists only on the `s-and-p-team/cortex` fork, as a convenience: one checkout that
carries the complete lineage support, so nobody has to merge the pieces by hand.

## What is in it

| piece | upstream PR | source branch |
|---|---|---|
| lineage telemetry plugin — two facts-only spans per HTTP exchange | [#761](https://github.com/rossoctl/cortex/pull/761) | `lane/lineage-telemetry-plugin` |
| lineage attach kit — attach lineage to any running Deployment | [#852](https://github.com/rossoctl/cortex/pull/852) | `feat/lineage-attach-kit` |
| lineage demo on the Weather Agent pair | not yet raised | `feat/lineage-demo-weather` (stacked on the kit) |

Base: `rossoctl/cortex` `main`. The two feature merges are ordinary merge commits, so
`git log --first-parent` shows exactly what was combined and each PR keeps its own history.

The three changesets are file-disjoint — the plugin lives under `authbridge/authlib/`,
`authbridge/cmd/`, `authbridge/docs/` and `authbridge/scripts/`; the kit and demo live under
`authbridge/lineage-attach/` and `authbridge/demos/lineage/`. The merges are conflict-free by
construction, not by luck.

## How to use it

```sh
git fetch origin
git checkout -b lineage/all-in-one origin/lineage/all-in-one
```

If you have an older local copy of `lane/lineage-telemetry-plugin`: **do not merge into it.**
That branch has been rebased and force-pushed several times, so an old copy shares almost no
history with the current one and a merge would resurrect dead commits. Check this branch out
fresh and delete the old one.

Start with `authbridge/lineage-attach/README.md` (attach to your own app) or
`authbridge/demos/lineage/README.md` (the ready-made weather-pair demo).

## Keeping it current

This branch is a snapshot. When #761 or #852 move, it is rebuilt the same way rather than
patched in place: branch from the new `main`, merge the two source branches, force-push.
Anything committed directly onto this branch will be lost in that rebuild — send fixes to the
source branch instead.
