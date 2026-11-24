# Roll out GitHub Actions policy changes

Use this checklist when changing which actions and reusable workflows GitHub
allows. Manage the Actions dependency policy separately from branch rules that
require workflows or passing checks.

## Before changing policy

- Save the effective repository and inherited Actions policy. Record the
  required check names and their expected GitHub Apps for each protected
  target, plus any rules that require particular workflows.
- List `uses:` references in `.github/workflows` and `.github/actions`
  on each supported protected branch, including release branches. Include
  release tags whose workflows you still expect to run or rerun: a tag can
  point to a different revision than the branch tip. Include the dependencies
  of composite actions and reusable workflows.
  Use reviewed full commit SHAs for external dependencies. If selecting
  individual actions, an action-specific `owner/action@*` entry can allow
  reviewed upgrades when paired with SHA enforcement. Pin reusable workflows
  to full commit SHAs yourself: GitHub's full-SHA setting for actions still
  permits tags in reusable workflow references.
- Before changing policy, test a normal fork PR and a PR in a real merge
  group. In the `CI (nix)` workflow, verify `Status (PR)` on `pull_request`
  and `Status (MQ)` on `merge_group`. Both jobs can appear on either event,
  but each evaluates its requirements only on its designated event. Confirm
  that the expected dependency jobs ran for each event. Check the live rules
  rather than assuming both status checks are required. Verify checks on the
  commits GitHub evaluates, including `merge_group.head_sha` for the queue.
  Use the real merge group to test the queue rather than a manual dispatch or
  a passing check on the PR head.

## Stage and verify

Use a staging repository if you have one. Apply SHA enforcement and
the selected dependency policy separately, starting at repository scope.
After each change, rerun the PR and queue checks and verify that the expected
apps report the required outcomes. Before widening the rollout, run or
coordinate smoke tests for workflows those checks don't cover, such as
publishing, backports, scheduled jobs, and bot requests.

If an action is blocked or a check fails to report, restore the previous
Actions policy, then rerun or requeue the test PR. Keep the queue and required
checks in place during rollback.

## Keep runners and credentials separated

Use fresh, isolated runners for jobs that process untrusted input. Prefer
GitHub-hosted runners where practical; for self-hosted runners, restrict the
runner group to trusted workflow definitions and provision a fresh machine
and storage per job. Keep those jobs away from trusted writable caches and
publishing credentials. A merge queue verifies a proposed code state; it
does not establish a publishing trust boundary.

When separating a worker from a publisher, start with read-only analysis.
Give a separate trusted publisher narrowly scoped credentials and have it
validate proposals against the triggering repository and object before
writing. Keep publication identity and downstream workflow triggers in the
smoke-test plan.

See GitHub's [Actions settings], [merge queue], and [secure use] guides.

[Actions settings]: https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/enabling-features-for-your-repository/managing-github-actions-settings-for-a-repository
[merge queue]: https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/configuring-pull-request-merges/managing-a-merge-queue
[secure use]: https://docs.github.com/en/actions/reference/security/secure-use
