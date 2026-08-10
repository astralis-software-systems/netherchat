# Contributing to Netherchat

Thanks for wanting to help. Bug reports, patches, and documentation fixes are all
welcome.

## Licensing of contributions

Netherchat is distributed under the **GNU Affero General Public License v3.0 or
later** (see [LICENSE](LICENSE)). Contributions are accepted under those same
terms — your patch is AGPL-3.0-or-later like the rest of the tree.

In addition, **by submitting a contribution you grant Astralis Software Systems a
perpetual, worldwide, irrevocable, royalty-free right to use, modify, and
relicense that contribution under other terms, including proprietary ones.** You
keep the copyright in your work; this grant is non-exclusive, so you remain free
to use your own contribution however you like.

This exists for one reason: Netherchat is dual-licensed. Astralis offers
commercial licenses to users for whom the AGPL does not fit, and that is only
possible if every line in the tree can be shipped under those terms too. Opening
a pull request is your agreement to the above — there is no separate CLA to sign.

If you cannot grant that (for example, your employer owns the copyright and will
not permit it), say so in the pull request before we review it. We would rather
know up front than unwind a merge.

## Before you open a pull request

`CLAUDE.md` is the working build-and-test guide; the short version:

```sh
gofmt -l .            # must print nothing
go vet ./...
go build ./...
go test -race ./...
just check-boundary   # the blind-relay import-graph guard
```

For the web client, run `npm run typecheck` and `npm run test` from `web/`.

- Branch off `main`, one logical change per branch, and open the pull request
  against `main`. All CI jobs must be green before a change merges.
- Use [Conventional Commits](https://www.conventionalcommits.org/) for commit
  subjects: `feat`, `fix`, `chore`, `docs`, `crypto`, `test`, `refactor`,
  optionally with a scope (`fix(tui): …`).
- If you change the wire format, update `PROTOCOL.md` in the same change.

## Two rules that are not style preferences

- **Do not import the client crypto package from any server-side package.** "The
  server cannot read message content" is a property of the build graph, enforced
  by `TestServerBinaryDoesNotLinkClientCrypto`. Crypto-free shared types go in
  `protocol/`.
- **Do not introduce a dependency that requires CGO.** All builds keep
  `CGO_ENABLED=0`, which is what makes the static binary, the `FROM scratch`
  image, and cross-compilation from any host possible.

## Security issues

Please do not open a public issue for a vulnerability. Contact
[Astralis Software Systems](https://astralis-systems.com) directly.
