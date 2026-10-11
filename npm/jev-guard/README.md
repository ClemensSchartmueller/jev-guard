# jev-guard installer

Run `npx --yes @clemensschartmueller/jev-guard@latest` from the project you want to protect. The launcher downloads the jev-guard GitHub Release matching its npm package version, checks the binary against that release's SHA256 manifest, installs it under `~/.jevguard/bin`, and runs `jev-guard init`.

Options after the package name go to `jev-guard init`. For example:

```sh
npx --yes @clemensschartmueller/jev-guard@latest --agent codex --scope project
```

See the [project README](https://github.com/ClemensSchartmueller/jev-guard#readme) for supported agents and other installation methods.

## Releasing

The `release.yml` workflow publishes this package only after the matching GitHub Release and its checksum file are uploaded. The npm package version must equal the Git tag without its leading `v`. The package configuration and workflow are ready for public publishing, but npm account setup remains with the owner:

1. Confirm that the npm user or organization scope `@clemensschartmueller` exists and that you can publish within it.
2. Bootstrap `@clemensschartmueller/jev-guard` once from `npm/jev-guard` with `npm publish --access public` using your npm account and interactive authentication. Use a package version with a matching GitHub Release and checksum file. Review the package with `npm pack --dry-run` before publishing.
3. In the new package's npm settings, configure a [GitHub Actions trusted publisher](https://docs.npmjs.com/trusted-publishers/) with organization/user `ClemensSchartmueller`, repository `jev-guard`, workflow filename `release.yml`, and permission to run `npm publish`. Configure it near the next release: npm requires its first successful trusted publish within two days.
4. For subsequent versions, create the matching Git tag and let `release.yml` publish via OIDC. Verify the npm package is public and installable. A published name/version cannot be reused, so bump the version for each later release.
