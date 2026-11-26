# oidc-caep-risc

A confidential OpenID Connect relying party for a traditional Java application, and a CAEP and RISC receiver on one Shared Signals poll stream. Authorization Code with PKCE (S256) is required. Client authentication is `client_secret_basic`, `client_secret_post`, or `private_key_jwt`. A public client (`none`) is refused.

`signals` defaults to on. `signals: false` turns CAEP and RISC off: the receiver does not start, transmitter metadata is not required, and the authorization request does not include `ssf.read` or `ssf.manage`. `DEFAULT_SCOPES` still names those two scopes. They are removed after that default is applied. The shipped demo omits `signals`, so they stay on.

The license is the MIT License in `LICENSE`. A pull request merged into `main` publishes the library (`library/` only; the demo never) to Maven Central after the test workflow succeeds on that commit. A direct push does not. `publish.yml` runs `mvn -Prelease -f library/pom.xml deploy` in the Maven container: the `release` profile adds the sources and javadoc jars, a GPG signature on every file, and the Central publishing plugin, which uploads, publishes and waits until the release is live. Maven Central has no trusted publishing, so the job uses four repository secrets: `CENTRAL_TOKEN_USERNAME` and `CENTRAL_TOKEN_PASSWORD` (a Central Portal user token) and `GPG_PRIVATE_KEY` and `GPG_PASSPHRASE` (the release signing key, whose public half is on a public key server). A release happens when the library's files changed since the last release's tag: `publish.yml` takes one patch above the highest published version, publishes it, and creates the matching tag and GitHub Release. A change to tests, the demo, or the docs releases nothing. To choose a version or start a new minor, raise `VERSION`; the version is stamped in CI and is not committed, so the manifests can trail what is published. `-Dcentral.skipPublishing=true` builds and signs everything and uploads nothing. `develop` may be ahead of `main`. This PEP work must not merge to `main` until `com.iyasec:iya-pep` is on Maven Central.

Bytecode 17 (`maven.compiler.release` 17). The test image is `maven:3.9-eclipse-temurin-26`. The runtime image is `eclipse-temurin:25-jre`. JSON is Jackson. Signatures are verified with the JDK (`Signature` and `Mac`). Do not wrap Spring Security, the Nimbus OIDC SDK, or Authlib.

## Layout

| Path | What it is |
|---|---|
| `pom.xml` | The aggregator: builds both modules, never published. Keep its version, the library's and the demo's equal to `VERSION`. |
| `library/` | `com.iyasec:oidc-caep-risc`, the library alone. Its `pom.xml` inherits nothing, so it is complete as published; its jar carries no demo class and no bundled dependency. Source in `library/src/main/java/com/iyasec/oidc`: `RelyingParty.java`, `ClientAuth.java`, `IdToken.java`, `Discovery.java`, `ssf/`. Tests in `library/src/test/java`: JUnit 5, a stub provider and a stub transmitter, no live iya-sts. |
| `demo/` | `com.iyasec:oidc-caep-risc-demo`, never published. `demo/src/main/java/com/iyasec/oidc/demo/Demo`, `demo/public/`, config `demo/oidc.json`. It shades one runnable jar, which the image runs as `/app/oidc-caep-risc.jar`. `demo/src/test/java/.../TrustChainTest` runs from the repository root: the install script writes the whole chain to `tlsCa`'s path, and the library trusts an HTTPS provider through that file. |
| `scripts` | `configure_iya_sts.py` registers the confidential client and writes the listener CA trust chain to the file `tlsCa` names. `trust_chain.py` holds `save_trust_chain()` and refreshes that file. Both are Python, including in this Java repository. |
| `Dockerfile`, `docker-compose.yml` | The demo image. Compose uses host networking. |

## Usage

```sh
docker build --target test .
```

```java
RelyingParty rp = RelyingParty.fromFile("oidc.json");
RelyingParty.Transaction request = rp.authorize();
RelyingParty.Login who = rp.complete(query, request);
```

Keep the transaction (`state`, nonce, code verifier) until the browser returns. Tokens stay in this process.

## Client profile (issue #25)

`Config.normalize` holds the defaults and checks, and `RelyingParty.create` runs it, so a map built in code gets the same rules as a file: `par` and `dpop` `auto`, `clockToleranceSec` 30, `maxIdTokenAgeSec` 600, `idTokenSigningAlgs` `["RS256"]`, `requireIdTokenTypAndAtHash` true, and the redirect-URI rule (https, or http on `localhost`, `127.0.0.1` or `[::1]`; `allowInsecure` does not relax it). A per-request redirect URI is held to the same rule. The JSON keys and defaults match the six sibling libraries; change them in all seven or none.

- DPoP is `Dpop.java`: an ES256 key generated at creation (or `dpopKey`, PKCS#8 or SEC 1 PEM; the public point is derived from the private scalar), proofs, and the latest `DPoP-Nonce` per origin. `RelyingParty.form()` signs a proof for PAR and every token request and retries one 400 `use_dpop_nonce`. `RelyingParty.resource()` presents a token (`DPoP` with `ath`, or `Bearer`) and retries one 401 `use_dpop_nonce`; `userinfo()` and `transmitterTransport(scope)` use it. `token()` refuses a `token_type` that does not match whether a proof was sent. `Http.Result` carries the response headers for this.
- `SignalsReceiver.Builder.transport()` routes every transmitter call; without it the receiver sends plain requests with the `headers` supplier, as before.
- `acr` is checked in `complete()` against `Transaction.acrValues`; `refresh()` does not check it.
- `require_pushed_authorization_requests` is kept by `Discovery`; `par: never` then fails at creation.
- `Discovery.idTokenAlgorithms(advertised, pinned, allowList)` narrows the allow-list to what the provider advertises; empty is an error at creation.
- `IdToken.validate` takes `requireTypAndAtHash`; UserInfo JWTs pass false.
- The session cache is `SessionStore` (`MemorySessionStore` by default) holding `SessionTokens`; `sessionAccessToken()` refreshes under a per-session lock when fewer than 30 seconds remain, and removes the entry when the refresh fails.
- The demo keeps each sign-in's tokens under its local session id, calls UserInfo through the cache, removes the entry on sign-out and on a session-ending event, and uses `transmitterTransport("ssf.manage")`. `scripts/configure_iya_sts.py` registers `oauthIdTokenSignedResponseAlg` RS256.

## Embedded PEP (#41)

iya-sts#1206. There is no feature flag: `library/pom.xml` depends on `com.iyasec:iya-pep:0.1.0`, and a build without it does not exist. `PepWiring` wires that package. Do not merge this to `main` until `iya-pep` is on Maven Central. The image clones `iya-pep-java` `develop` and installs it before `mvn`, in the test stage and in the build stage. A build fails until that branch is pushed.

- A `pep` object is off when absent. `Config.resolveConfig` and `Config.normalize` keep it. A section that is not an object is refused (`pep must be an object`).
- `RelyingParty.create` calls `PepWiring.build` after the `private_key_jwt` key is loaded and `dpopFor` has returned, then `pep.start()`. `PepConfig.fromJson` gets the issuer (realm prefix included) as `pdpUrl`'s default and `clientId` as `application`'s default. A section that omits `signals` is set from this library's `signals` (false only when `signals` is false). A section that omits `tlsCa` receives this library's `tlsCa` only when that value is a PEM block (`-----BEGIN`).
- The assertion key must be the PEP's own. After `Pep.create`, before `start`, the thumbprint is compared with `SigningKey.pemThumbprint` of `privateKeyPem` and, when a live `Dpop` exists, with `dpop.thumbprint()`. The refusals are `pep.assertionKey is the private_key_jwt key; the PEP needs a key of its own` and `pep.assertionKey is the DPoP key; the PEP needs a key of its own`.
- `decide(login, access)` and `decide(login, access, userinfo)` adapt the sign-in with `PepWiring.subjectWithUserinfo`. The id is the `username` claim, else `preferredUsername`, else `sub`. Properties are the ID token claims, with userinfo laid over. There is no `decideSession`: the session store holds `SessionTokens` only. With no `pep` section, `decide` throws `OidcError` code `config` (`no pep section is configured`). `pep.decide` never throws. `Decision.httpStatus()` is 200 only for a permit, otherwise 403.
- `SignalsReceiver`'s constructor, given `.relyingParty(rp)`, adds `Pep.POLICIES_CHANGED_EVENT` (`urn:iya:sts:secevent:event-type:pep-policies-changed`) and hands each verified payload to `onPolicyEvent` when `PepWiring.wantsEvents` is true (`Mode.LOCAL`, or `permitCacheMs` greater than 0). `setEventStream` runs at `start` (`REQUESTED` or `EXCLUDED`), after a poll that succeeds, and as `DOWN` after a poll that fails and on `stop`. A reused stream is PATCHed for the event types it lacks. A refusal is noted and the receiver still starts.
- Add Subject and Remove Subject follow a person (`iss_sub` with the transmitter issuer and `person`, else `email`). A refusal never fails sign-in. When the PEP wants events, `start` also adds the application as `{"format":"opaque","id":<application>}` and never removes it. `ssf.addSubjects: false` turns the calls off.

The guide is `docs/remote-pep.md`. `scripts/configure_iya_sts.py --pep` and `scripts/live_iya_sts.py --pep` are the install and the live run.

## Credentials

README.md's `## Credentials` (the application's own, the embedded PEP's, install-time only, trust material, development and product) lists every key, certificate, password and secret, where each lives and how to rotate it. `docs/remote-pep.md`'s `## Credentials` has the PEP half in detail: the account, the key, the three token audiences and scopes, and why the key must differ. Keep both in step with `scripts/configure_iya_sts.py`, `Config` (the `pep` section and `ssf.addSubjects`), `PepWiring` (the key check) and `RelyingParty.create`.

## Errors

`Caught.error` records a caught exception through `java.lang.System.Logger`, including the stack, and the method then throws the `OidcError` it already threw. The caught exception is the cause. `Caught.warn` is the same record when the method recovers and does not throw: a later signing key, a poll retry, a false verification, sign-out cleanup, or a handler that must still acknowledge the Security Event Token. A `catch (OidcError)` that only throws that error again is not logged a second time.

## Tests

```sh
docker build --target test .
```

The `test` stage runs `mvn -B test` (both modules) in `maven:3.9-eclipse-temurin-26`. Before that it clones `iya-pep-java` `develop` and runs `mvn -B -f /opt/iya-pep/pom.xml -DskipTests install`. The build stage does the same install, so the demo image can compile. GitHub Actions uses `mvn -B test`. Do not run Maven on the host. The demo stage packages with `-DskipTests` in its own Maven image. The runtime image is `eclipse-temurin:25-jre`.

The stub tests do not start iya-sts. The `test` stage installs `python3` and `openssl` for `TrustChainTest`. The scripts need only Python's standard library and the `openssl` command: no `pip install` on the host, and no `python3-cryptography` in either image. `python3 scripts/live_iya_sts.py` does start one, unless `IYA_STS_URL` names one that is already running. It runs the install script on the host in a scratch copy of this checkout (it writes the `tlsCa` chain), then builds the demo image (which carries the chain), starts it with `TLS_CA_REFRESH=0` and no CA mount, signs the demo in and checks two Shared Signals events on `GET /live-status`. The nightly workflow runs both. It never binds port 3000, 8081 or 18481-18495; the defaults are 18544 and 18644. Secrets go to `docker run` as `-e NAME`. No script prints a password or secret, or a URL (trace lines carry fixed labels); the client secret and a generated test-user password (`demo/generated/<user>.password`) are files created 0600, and only the password file's path is printed. Every `ssl` context in `scripts/` sets TLS 1.2 as the minimum.

## The iya-sts trust chain (`tlsCa`)

`tlsCa` in `demo/oidc.json` names the iya-sts TLS listener CA trust chain the library trusts. The default is `generated/idp-ca.pem`, relative to `demo/`. The value may also be `file:<path>`, `env:<NAME>`, or the PEM itself. The library adds every certificate in it (`CertificateFactory.generateCertificates`, every PEM block) to the JDK's default trust store, so a reissued listener certificate under the same CA is still trusted.

`scripts/configure_iya_sts.py`, the install script, writes that file. It saves the whole chain iya-sts publishes at `GET /tls/server-certificate` (leaf, TLS Issuing CA, Intermediate, Root), or the chain from the TLS handshake when that path does not answer. It prints the path, the trust anchor's subject and its SHA-256 fingerprint. Compare the anchor with the Root CA on iya-sts's PKI page.

The demo image build copies that file into the image at `/app/demo/generated/idp-ca.pem`, so the image trusts that iya-sts with no bind mount and no fetch. Run the install script before you build the image. Rebuild the image after running the install script against a different iya-sts. `.dockerignore` admits only that file from `demo/generated`. The client secret stays out of the image; compose mounts `demo/generated` at run time. A build with no chain file yet (a fresh clone, CI) still succeeds; the image then has no `tlsCa` file.

The container entrypoint also refreshes the file from the provider at start, because a development iya-sts makes a new CA when it restarts. A failed refresh keeps the file from the build. `TLS_CA_REFRESH=0` turns the refresh off. `python3 scripts/trust_chain.py --config demo/oidc.json` refreshes it by hand.

The mechanism is `COPY demo demo` plus `.dockerignore`'s `demo/generated/*` and `!demo/generated/idp-ca.pem`. Do not replace it with a COPY that names the file or globs for it: when the file is absent, BuildKit fails on the missing `demo/generated` and the classic builder fails with "no source files were specified". A directory COPY of `demo/` (which always exists) succeeds in both. Before this change `.dockerignore` did not exclude `demo/generated`, so a demo image built after the install script carried the client secret.

## Demo

`docker-compose.yml` sets `network_mode: host`. The process binds `PORT`, default 3000. `ENV PORT=3000` in the image keeps an unset value on 3000, and the health check calls `http://127.0.0.1:${PORT}/healthz`.

```sh
docker compose up --build
```

`GET /healthz` returns `ok`. `GET /` is the page. `GET /login` redirects to the provider. `GET /callback` completes the sign-in. `POST /logout` ends the local session. `GET /live-status` reports the sign-in and the Shared Signals events this process has accepted. It does not include tokens.

A loopback redirect follows `PORT` in the running server and in `scripts/configure_iya_sts.py`. Any other host is left as written. An explicit `--public-url` or a non-empty `PUBLIC_URL` replaces the origin and keeps the path. The running container's `PORT` wins over the shell's when the script registers the application. `pollIntervalMs` is a millisecond pause, not a port.

Open `http://127.0.0.1:$PORT` after the provider is up. Do not bind port 3000 or 8081 while another demo or iya-sts is already using them.
