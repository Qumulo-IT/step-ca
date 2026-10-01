# Qumulo-IT/step-ca

Fork of [smallstep/certificates](https://github.com/smallstep/certificates) used by wile-e.

- `master` mirrors upstream.
- `wile-e/patches` is the latest upstream release plus one commit (async ACME finalization, smallstep/certificates#2636). Tags: `vX.Y.Z-wile.N`.
- `.github/workflows/sync.yml` rebases the patch onto each new upstream release and opens a PR in Qumulo-IT/wile-e.

## GitHub App

The org disallows PATs; the workflow mints an installation token with `actions/create-github-app-token`.

- App permissions (Repository): Contents rw, Workflows rw, Pull requests rw, Issues rw, Metadata r.
- Install on Qumulo-IT/step-ca and Qumulo-IT/wile-e only.
- On Qumulo-IT/step-ca: repo variable `WILE_E_SYNC_APP_ID`, secret `WILE_E_SYNC_APP_PRIVATE_KEY`.
- The failure issue uses `github.token`.
