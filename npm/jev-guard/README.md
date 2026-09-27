# jev-guard installer

Run `npx --yes jev-guard@latest` from the project you want to protect. The launcher downloads the jev-guard GitHub Release matching its npm package version, checks the binary against that release's SHA256 manifest, installs it under `~/.jevguard/bin`, and runs `jev-guard init`.

Options after the package name go to `jev-guard init`. For example:

```sh
npx --yes jev-guard@latest --agent codex --scope project
```

See the [project README](https://github.com/ClemensSchartmueller/jev-guard#readme) for supported agents and other installation methods.

## Releasing

The `release.yml` workflow publishes this package only after the matching GitHub Release and its checksum file are uploaded. Before the first npm release, a maintainer must claim the `jev-guard` package name and configure an [npm trusted publisher](https://docs.npmjs.com/trusted-publishers/) for GitHub repository `ClemensSchartmueller/jev-guard` and workflow `release.yml`. The npm package version must equal the Git tag without its leading `v`.
