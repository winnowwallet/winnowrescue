# Production site deployment

The `site` workflow accepts pushes to `main` affecting the site, Wrangler
configuration or deployment workflow, and manual runs with `main` selected.
The deploy job checks the repository, full branch ref and event type before
any steps run. Its first step checks the branch ref case-sensitively, because
GitHub Actions expression string comparisons ignore case. Checkout uses
`github.sha`, the exact commit associated with the allowed main run, including
on retries; it does not resolve a newer branch tip.

## Production environment

These workflow checks do not enforce a security boundary against repository
writers: a writer can alter the workflow on another branch and reference
repository-level secrets. The deploy job therefore references the separately
configured `production` environment.

With owner approval on 2026-10-19, the environment was configured and verified
with Selected branches and tags, one Branch rule for `main`, no Tag rules,
and Alex Newman (`posix4e`, GitHub user ID `806363`) as its required reviewer.
Administrator bypass is disabled. Self-review is permitted so Alex can
approve a deployment he triggered. No credentials or variables were added.

Keep those protections in place. Do not choose Protected branches only while
no branch protections exist: GitHub then allows all branches. Main remains
unprotected; changing branch protection is outside this change's approval.

## Required before enabling production credentials

Credential creation and storage require separate owner approval. Store future
`CF_API_TOKEN` and `CF_ACCOUNT_ID` in the `production` environment, not as
repository-level secrets, and verify the environment protections first.

Scope the Cloudflare token to the intended account and only the Workers and
zone permissions needed by `winnow-rescue` and `rescue.winnowwallet.com`.
This is an assets-only Worker without KV, R2 or D1 bindings; do not grant
access to those products for this deployment.

The environment reference was added only after the approved environment and
its protections existed. A workflow reference to a nonexistent environment
can create it automatically without protection rules; recreate and verify
the approved protections before running this workflow if it is ever deleted.
No production deployment or deployment review was performed for this change.

See GitHub's documentation on [expression comparisons](https://docs.github.com/en/actions/reference/workflows-and-actions/expressions),
[deployment branch policies](https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments#deployment-branches-and-tags)
and [environment creation and secrets](https://docs.github.com/en/actions/how-tos/deploy/configure-and-manage-deployments/manage-environments).
