# Qumulo-IT/step-ca

Fork of [smallstep/certificates](https://github.com/smallstep/certificates) used by wile-e.

- `master` mirrors upstream.
- `wile-e/patches` is the latest upstream release plus one commit (async ACME finalization, smallstep/certificates#2636). Tags: `vX.Y.Z-wile.N`.
- `.github/workflows/sync.yml` rebases the patch onto each new upstream release and opens a PR in Qumulo-IT/wile-e.

## Secret

`WILE_E_PR_TOKEN` (fine-grained token): Qumulo-IT/step-ca contents + workflows write; Qumulo-IT/wile-e contents + pull-requests write. Used for all pushes and the PR; the failure issue uses `github.token`.
