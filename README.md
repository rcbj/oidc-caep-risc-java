# oidc-caep-risc

A confidential OpenID Connect relying party for a traditional Java application, and a CAEP and RISC receiver on one Shared Signals poll stream. Authorization Code with PKCE (S256) is required. Client authentication is `client_secret_basic`, `client_secret_post`, or `private_key_jwt`. A public client (`tokenEndpointAuthMethod` `"none"`) is refused. JSON Web Signature uses the JDK (JCA). This library does not wrap an OpenID Connect framework.

JSON configuration keys are the same names the Node library `oidc-caep-risc-nodejs` reads. `signals` omitted or `true` keeps CAEP and RISC on. `signals: false` does not start the receiver, does not require transmitter metadata, and drops `ssf.read` and `ssf.manage` from the scope list after the default scopes are applied. `DEFAULT_SCOPES` still names those two scopes. The shipped demo leaves `signals` on (the key is omitted).

The license is MIT. `develop` and `main` are the same commit. A pull request merged into `main` publishes the library (`library/` only; the demo never) to Maven Central after the test workflow succeeds on that commit. A direct push does not. `publish.yml` runs `mvn -Prelease -f library/pom.xml deploy` in the Maven container: the `release` profile adds the sources and javadoc jars, a GPG signature on every file, and the Central publishing plugin, which uploads, publishes and waits until the release is live. Maven Central has no trusted publishing, so the job uses four repository secrets: `CENTRAL_TOKEN_USERNAME` and `CENTRAL_TOKEN_PASSWORD` (a Central Portal user token) and `GPG_PRIVATE_KEY` and `GPG_PASSPHRASE` (the release signing key, whose public half is on a public key server). A release on Central is permanent: a version already there is skipped, and the next release is a new version in `VERSION` and the three poms. `-Dcentral.skipPublishing=true` builds and signs everything and uploads nothing.

## Usage

Java 17. Group `com.iyasec`, artifact `oidc-caep-risc`, version `0.1.0`.

```java
RelyingParty rp = RelyingParty.fromFile("oidc.json");
RelyingParty.Transaction request = rp.authorize();
// redirect the browser to request.url; keep state, nonce, and codeVerifier
RelyingParty.Login who = rp.complete(query, request);
```

Tokens stay in this process. Keep the transaction until the browser returns.

## Settings and defaults

These defaults and checks apply whether the relying party is created from a file (`RelyingParty.fromFile`, `Config.resolveConfig`) or directly from a map (`RelyingParty.create`, which runs `Config.normalize`). The same JSON keys and defaults are used by the six sibling libraries.

| Key | Default | Meaning |
|---|---|---|
| `par` | `auto` | `auto` pushes the authorization request when the provider has a pushed authorization endpoint, and always when it sets `require_pushed_authorization_requests`. `always` fails at creation without the endpoint. `never` fails at creation when the provider requires PAR. |
| `dpop` | `auto` | RFC 9449. `auto` uses DPoP when the provider's `dpop_signing_alg_values_supported` includes ES256. `always` fails at creation otherwise. `never` sends no proofs. |
| `dpopKey` | unset | A P-256 private key in PEM (PKCS#8 or SEC 1), as the PEM itself, `file:<path>`, `env:<NAME>` or a path. Unset, the key is generated when the relying party is created and held in memory only. Name one when several processes share sessions. |
| `idTokenSigningAlgs` | `["RS256"]` | The ID token algorithms accepted, narrowed to the ones the provider advertises. `none` is refused. A symmetric algorithm (HS256, HS384, HS512) is accepted only when it is named here. |
| `idTokenSignedResponseAlg` | unset | One pinned algorithm. It must be advertised, and it replaces the list above. |
| `requireIdTokenTypAndAtHash` | `true` | The ID token header must carry `typ` `JWT` or `application/jwt`, and when the token response has an access token the ID token must carry a matching `at_hash`. `false` checks both only when present. |
| `acrValues` | unset | `acr_values` for every authorization request (a string or a list). `AuthorizeOptions.acrValues` overrides it per request. |
| `clockToleranceSec` | 30 | Clock skew allowed on `exp`, `nbf` and `iat`. An `iat` more than this far in the future is refused. |
| `maxIdTokenAgeSec` | 600 | The oldest `iat` accepted. |

`redirectUri`, `postLogoutRedirectUri` and a per-request `AuthorizeOptions.redirectUri` must be https, or http on a loopback host (`localhost`, `127.0.0.1`, `[::1]`). `allowInsecure` does not relax this rule; it still allows an http provider.

## DPoP

When DPoP is in use, a proof (`typ` `dpop+jwt`, the public `jwk`, `jti`, `htm`, `htu` without query or fragment, `iat`) goes on the PAR request and on every token request (code, refresh and client credentials). The authorization request carries `dpop_jkt`, in the PAR body when PAR is used. The token response's `token_type` must be `DPoP`; without DPoP it must be `Bearer`; a mismatch is refused.

A DPoP token is presented as `Authorization: DPoP` with a proof that carries `ath`: `userinfo(accessToken, tokenType, sub)`, `resource(method, url, headers, body, accessToken, tokenType)`, and every call the Shared Signals receiver makes through `transmitterTransport(scope)`. A 400 `use_dpop_nonce` from the authorization server, or a 401 whose `WWW-Authenticate` is `DPoP error="use_dpop_nonce"` from a resource server, is retried once with the `DPoP-Nonce` it gave. The latest nonce is kept per server origin and sent on the next proof.

```java
SignalsReceiver receiver = SignalsReceiver.builder(transmitter, onEnd)
        .tls(rp.tls())
        .transport(rp.transmitterTransport("ssf.manage"))
        .build();
```

## acr

When `acr_values` is requested, the ID token from the code exchange must carry `acr`, and it must be one of the requested values. The values are kept in the transaction (`Transaction.acrValues`; keep it with the state). A refresh does not check `acr` again.

## The sign-in token cache

`complete(query, transaction, sessionId)` keeps the sign-in's tokens under the application's session identifier. `complete(query, transaction)` keeps them under a new random handle, returned as `Login.sessionId`. `sessionAccessToken(sessionId)` returns the cached access token while it has more than 30 seconds left, and otherwise refreshes it (with a DPoP proof when DPoP is in use) and updates the cache. A failed refresh removes the entry and throws `OidcError` with code `session`. `removeSession(sessionId)` clears the entry: call it on sign-out and from the receiver's `onEndSessions` callback (a CAEP `session-revoked`). The default store is `MemorySessionStore`; `rp.sessionStore(store)` installs any `SessionStore`, for example one shared by several processes.

```java
RelyingParty.Login who = rp.complete(query, request, localSessionId);
RelyingParty.Credentials token = rp.sessionAccessToken(localSessionId);
Map<String, Object> claims = rp.userinfo(token.accessToken, token.tokenType, who.subject);
```

## Errors

A caught exception is written to `java.lang.System.Logger` with its stack. The JDK sends that logger to `java.util.logging` unless the application installs a `System.LoggerFinder`. Where this library already threw `OidcError`, it still throws `OidcError`, and the caught exception is the cause.

A catch that recovers does not throw. It is still logged. A poll is retried, the next signing key is tried, an HTTP error body is read, sign-out still finishes after a revoke fails, and a Shared Signals handler that throws does not stop acknowledgement of that event. Passing a `OidcError` through is not logged again: the foreign exception was logged where it was caught.

## Tests

```sh
docker build --target test .
```

The suite runs in a container. The tests build an in-process stub provider and a stub transmitter. They do not start iya-sts. `TrustChainTest` runs the install script's trust-chain code (Python, installed in the `test` stage) against an HTTPS stub on a four-certificate chain, and checks the library trusts the stub through the file it wrote.

`python3 scripts/live_iya_sts.py` is the live half. It starts iya-sts when `IYA_STS_URL` is unset, runs the install script on the host in a scratch copy of this checkout (it registers the demo and writes the `tlsCa` chain), then builds this demo image from it, checks the image carries the chain, starts the demo with no CA mount and `TLS_CA_REFRESH=0`, signs in, and requires a credential-change event and a session-revoked event on `GET /live-status`. The second event ends the local session. It never binds port 3000, 8081 or 18481-18495; its defaults are 18544 (`LIVE_STS_PORT`) and 18644 (`LIVE_DEMO_PORT`). It needs `python3` (standard library only), `openssl` and Docker on the host, and installs nothing. When the install script generates a test-user password it writes it to `demo/generated/<user>.password` (mode 0600) and prints only that path. The nightly workflow runs the unit suite and this script.

## Layout

| Path | What it is |
|---|---|
| `library/` | The library, `com.iyasec:oidc-caep-risc`, nothing else in its jar. `RelyingParty`, `ClientAuth`, `IdToken`, `Discovery`, `Config`, `ssf/` in `library/src/main/java/com/iyasec/oidc`; JUnit 5 ports of the Node relying-party and Shared Signals tests in `library/src/test/java`. |
| `demo/` | The demo module, never published: `com.iyasec.oidc.demo.Demo`, config `demo/oidc.json`. |
| `scripts/configure_iya_sts.py` | Registers the confidential client on iya-sts with `id_token_signed_response_alg` RS256. The Java repo runs this Python registrar. Loopback redirects follow the running container's `PORT`, then the shell `PORT`. |
| `Dockerfile`, `docker-compose.yml` | The demo image. Compose uses host networking. |

## The iya-sts trust chain (`tlsCa`)

`tlsCa` in `demo/oidc.json` names the iya-sts TLS listener CA trust chain the library trusts. The default is `generated/idp-ca.pem`, relative to `demo/`. The value may also be `file:<path>`, `env:<NAME>`, or the PEM itself. The library adds every certificate in it (`CertificateFactory.generateCertificates`, every PEM block) to the JDK's default trust store, so a reissued listener certificate under the same CA is still trusted.

`scripts/configure_iya_sts.py`, the install script, writes that file. It saves the whole chain iya-sts publishes at `GET /tls/server-certificate` (leaf, TLS Issuing CA, Intermediate, Root), or the chain from the TLS handshake when that path does not answer. It prints the path, the trust anchor's subject and its SHA-256 fingerprint. Compare the anchor with the Root CA on iya-sts's PKI page.

The demo image build copies that file into the image at `/app/demo/generated/idp-ca.pem`, so the image trusts that iya-sts with no bind mount and no fetch. Run the install script before you build the image. Rebuild the image after running the install script against a different iya-sts. `.dockerignore` admits only that file from `demo/generated`. The client secret stays out of the image; compose mounts `demo/generated` at run time. A build with no chain file yet (a fresh clone, CI) still succeeds; the image then has no `tlsCa` file.

The container entrypoint also refreshes the file from the provider at start, because a development iya-sts makes a new CA when it restarts. A failed refresh keeps the file from the build. `TLS_CA_REFRESH=0` turns the refresh off. `python3 scripts/trust_chain.py --config demo/oidc.json` refreshes it by hand.

## Demo

`PORT` defaults to 3000. A loopback redirect and post-logout URL follow `PORT`. Any other host is left as written. An explicit `PUBLIC_URL` or `--public-url` replaces the origin and keeps the path. The default `http://localhost:3000` is not an explicit public URL.

```sh
docker compose up --build
```

`GET /healthz` returns `ok`. `GET /` is the page. `GET /login` starts `authorize` and redirects. `GET /callback` completes the code exchange. `POST /logout` signs the local session out. `GET /live-status` is JSON for the sign-in and the Shared Signals events this process has accepted. It does not include tokens. When signed in it also reports the token type and the last UserInfo result. The page calls UserInfo with the session's token from the relying party's session cache, with a DPoP proof when the token is DPoP-bound. The receiver calls the transmitter through `transmitterTransport("ssf.manage")`. Sign-out and a session-ending Shared Signals event remove the session's cache entry.

`docker-compose.yml` sets `network_mode: host`. The image sets `ENV PORT=3000`. The health check calls `http://127.0.0.1:${PORT}/healthz`. The running container's `PORT` wins over the shell's when `scripts/configure_iya_sts.py` registers the application.

Demo JSON uses `file:` and the configuration's own placeholders. It does not contain a generated secret or key.
