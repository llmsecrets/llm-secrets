# Release & Publishing

## Source of truth: main, always

Every published artifact — the Docker Hub image
(`joshgottlieb/scrt4-hardened`), the install wrapper served at
`install.llmsecrets.com`, and any future binaries — is built from the
**main** branch. Nothing ships from a feature or fix branch.

If you want a change to reach users, it has to merge to main first.

This is not just convention. It's enforced:

1. `.github/workflows/docker-publish.yml` listens only on `push` to `main`
   (plus version tags on main and `workflow_dispatch`). Feature branches
   cannot trigger a publish.
2. The `build-and-push` job has `if: github.ref == 'refs/heads/main' || startsWith(github.ref, 'refs/tags/v')`
   as a second-line guard. Even if a misconfigured workflow dispatch or
   fork-PR ever queues the workflow on a non-main ref, the job body does
   not run and Docker Hub credentials are never exposed.
3. `.github/workflows/guard-publish-triggers.yml` runs on every PR and
   fails if someone re-adds a non-main branch to the `on.push.branches`
   list of `docker-publish.yml`. This is the "no silent drift" tripwire.

## How to ship a change to the hardened image

```text
  feature branch  →  PR to main  →  merge  →  docker-publish.yml runs
                                              (triggered by daemon/** or
                                              Dockerfile.hardened changes)
                                              →  new :latest on Docker Hub
```

A user picks up the new image with:

```bash
docker rm -f scrt4
scrt4   # or: curl -fsSL https://install.llmsecrets.com | sh
```

The host wrapper pulls the latest image on first run.

### What triggers a rebuild

The docker-publish workflow fires on push to main when any of these paths
change:

- `daemon/**` — the Rust daemon or the bash CLI (`daemon/bin/scrt4`)
- `Dockerfile.hardened` — the image definition itself
- `.github/workflows/docker-publish.yml` — the workflow itself

Documentation-only changes (`*.md`, `install/**`, etc.) do **not** rebuild
the image — they only affect the install wrapper served by Caddy.

### Manual rebuild

If you need to republish the image without a source change (e.g. after a
base-image CVE), trigger the workflow by hand:

```bash
gh workflow run "Build and Publish Docker Images" --ref main
```

## Why this document exists

Earlier we had two parallel histories: the install wrapper lived on main,
but the hardened-image build pipeline lived on a feature branch.
Fixes merged to main didn't rebuild the image. A bug fix could land on
main, pass CI, be tagged "done," and still not reach users — because the
pipeline was watching the wrong branch.

The rule is now: **if it's not on main, it's not shipped**. If you find
yourself editing Dockerfile.hardened or docker-publish.yml on a feature
branch, that's fine — but the PR has to land on main before any user
sees the change.

## What happens if a non-main branch tries to publish

- The workflow's `on.push.branches` doesn't include it → no trigger.
- Even if `workflow_dispatch` is invoked on a non-main ref, the `if:` on
  the job skips all steps → no Docker login, no build, no push.
- The `guard-publish-triggers` workflow on every PR asserts the allow-list
  has not grown beyond `main`.

Three layers of defense. Don't remove any of them without updating this
document and telling the team why.
