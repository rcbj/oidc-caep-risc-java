# oidc-caep-risc

A confidential OpenID Connect relying party for a traditional Java application, and a CAEP and RISC receiver on one Shared Signals poll stream. Authorization Code with PKCE (S256) is required. Client authentication is `client_secret_basic`, `client_secret_post`, or `private_key_jwt`. A public client (`tokenEndpointAuthMethod` `"none"`) is refused. JSON Web Signature uses the JDK (JCA). This library does not wrap an OpenID Connect framework.

JSON configuration keys are the same names the Node library `oidc-caep-risc-nodejs` reads. `signals` omitted or `true` keeps CAEP and RISC on. `signals: false` does not start the receiver, does not require transmitter metadata, and drops `ssf.read` and `ssf.manage` from the scope list after the default scopes are applied. `DEFAULT_SCOPES` still names those two scopes. The shipped demo leaves `signals` on (the key is omitted).

The license is MIT. `develop` may be ahead of `main`. This PEP work must not merge to `main` until `com.iyasec:iya-pep` is on Maven Central. A pull request merged into `main` publishes the library (`library/` only; the demo never) to Maven Central after the test workflow succeeds on that commit. A direct push does not. `publish.yml` runs `mvn -Prelease -f library/pom.xml deploy` in the Maven container: the `release` profile adds the sources and javadoc jars, a GPG signature on every file, and the Central publishing plugin, which uploads, publishes and waits until the release is live. Maven Central has no trusted publishing, so the job uses four repository secrets: `CENTRAL_TOKEN_USERNAME` and `CENTRAL_TOKEN_PASSWORD` (a Central Portal user token) and `GPG_PRIVATE_KEY` and `GPG_PASSPHRASE` (the release signing key, whose public half is on a public key server). A release happens when the library's files changed since the last release's tag: `publish.yml` takes one patch above the highest published version, publishes it, and creates the matching tag and GitHub Release. A change to tests, the demo, or the docs releases nothing. To choose a version or start a new minor, raise `VERSION`; the version is stamped in CI and is not committed, so the manifests can trail what is published. `-Dcentral.skipPublishing=true` builds and signs everything and uploads nothing.

## Usage

Java 17. Group `com.iyasec`, artifact `oidc-caep-risc`, version `0.2.0`.

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

## Embedded PEP

Ask iya-sts's authorization policy whether a signed-in person may act on a resource, through the embedded Remote PEP (the shared [`iya-pep`](https://github.com/rcbj/iya-pep-java) package, `com.iyasec:iya-pep:0.1.0`; iya-sts [#1206](https://github.com/rcbj/iya-sts/issues/1206)). There is no feature flag: the dependency is always on. **[docs/remote-pep.md](docs/remote-pep.md) is the full guide.** Do not merge this to `main` until that package is on Maven Central.

```json
"pep": { "name": "pep-orders", "mode": "local", "assertionKey": "demo/generated/pep-key.pem" }
```

```java
Decision decision = rp.decide(login, Access.of("read", "order", orderId), userinfo);
int status = decision.httpStatus(); // 200 for a permit, 403 for a deny and for any PEP failure
if (decision.isPermit()) {
    // serve
}
```

The section is off unless present. A section without `mode` is `local`. `Decision.httpStatus()` is 200 only for a permit. The demo protects `GET /orders/<id>` and `GET /attribute-protected` and answers with `httpStatus()`. `GET /live-status` carries `pep.status()` under `pep`.

## Errors

A caught exception is written to `java.lang.System.Logger` with its stack. The JDK sends that logger to `java.util.logging` unless the application installs a `System.LoggerFinder`. Where this library already threw `OidcError`, it still throws `OidcError`, and the caught exception is the cause.

A catch that recovers does not throw. It is still logged. A poll is retried, the next signing key is tried, an HTTP error body is read, sign-out still finishes after a revoke fails, and a Shared Signals handler that throws does not stop acknowledgement of that event. Passing a `OidcError` through is not logged again: the foreign exception was logged where it was caught.

## Tests

```sh
docker build --target test .
```

The suite runs in a container. The tests build an in-process stub provider and a stub transmitter. They do not start iya-sts. `TrustChainTest` runs the install script's trust-chain code (Python, installed in the `test` stage) against an HTTPS stub on a four-certificate chain, and checks the library trusts the stub through the file it wrote.

`python3 scripts/live_iya_sts.py` is the live half. It starts iya-sts when `IYA_STS_URL` is unset, runs the install script on the host in a scratch copy of this checkout (it registers the demo and writes the `tlsCa` chain), then builds this demo image from it, checks the image carries the chain, starts the demo with no CA mount and `TLS_CA_REFRESH=0`, signs in, and requires a credential-change event and a session-revoked event on `GET /live-status`. The second event ends the local session. It never binds port 3000, 8081 or 18481-18495; its defaults are 18544 (`LIVE_STS_PORT`) and 18644 (`LIVE_DEMO_PORT`). It needs `python3` (standard library only), `openssl` and Docker on the host, and installs nothing. When the install script generates a test-user password it writes it to `demo/generated/<user>.password` (mode 0600) and prints only that path. The nightly workflow runs the unit suite and this script. `python3 scripts/live_iya_sts.py --pep` (or `LIVE_PEP=1`) adds the embedded PEP: `GET /orders/42` is 200 and `POST /orders/42` is 403, `GET /attribute-protected` is 200 for `oidc-demo-user` and 403 for `oidc-demo-denied`, in `central` and then in `local`, and a policy change arrives as `pep-policies-changed`.

## Credentials

Every credential the library, the demo and the install script use, who makes it, where it lives and what it proves. No value of any of them is ever printed, logged, put in an image or written into this repository: the files below are created 0600 under `demo/generated/`, which `.gitignore` excludes and `.dockerignore` keeps out of the image (only `demo/generated/idp-ca.pem`, a public trust chain, goes in).

### The application's own credentials

The relying party is the confidential OAuth client `oidc-caep-risc-demo` (`clientId` in `demo/oidc.json`). These credentials are the application's, used for signing people in and for its Shared Signals stream.

| Credential | Type / algorithm | Made or issued by | Where it lives | Used for | How iya-sts learns of it | Rotation |
|---|---|---|---|---|---|---|
| Client ID | a name, not a secret | the install script registers it (`applications/create`) | `clientId` in `demo/oidc.json` | naming the client at the authorization and token endpoints | the registration | — |
| Client secret | a random string (`secrets.token_urlsafe(32)`), sent as `client_secret_basic` (default) or `client_secret_post` (`tokenEndpointAuthMethod`) | the install script, on the run that creates the application | `clientSecret: "file:generated/client-secret"`, i.e. `demo/generated/client-secret`, 0600 (also accepted: `env:NAME`, or the value itself) | authenticating the client at the token endpoint: the code exchange, refresh, and the client-credentials grant below | sent once, as `oauthClientSecret` in the create call | the script never rotates it: a re-run keeps the file, and refuses when the application exists but the file is gone. Set a new secret on the application in iya-sts, put it in the file, restart the demo |
| `private_key_jwt` key (optional) | a private key in PEM; the assertion is signed with `privateKeyAlg` (default `RS256`), `iss` = `sub` = the client ID, `aud` = the endpoint, a fresh `jti`, 60 s lifetime | you | `privateKey` (inline PEM, `file:`, `env:`, or a path), with `tokenEndpointAuthMethod: "private_key_jwt"` | client authentication instead of the secret | not by the install script: register the public key on the application yourself | make a new key, register its public half, replace the file, restart |
| DPoP key | ES256 (P-256) | generated in memory when the relying party is created, or yours in `dpopKey` (inline PEM, `file:`, `env:`, or a path) | memory only, or wherever `dpopKey` points (shared by several processes) | binding every token the client gets (RFC 9449): proofs on PAR and token requests, `dpop_jkt` on the authorization request, and `Authorization: DPoP` with a proof on UserInfo and transmitter calls. `dpop`: `auto` (when the provider lists ES256), `always`, `never` | its public key travels in each proof; the token is bound to its thumbprint | the generated key is new at every start; for `dpopKey`, replace the key and restart. Tokens bound to the old key are no longer usable |
| The Shared Signals token | an access token from the client-credentials grant, scope `ssf.manage`, DPoP-bound when DPoP is on | iya-sts, to the client authenticated as above | memory only | every call `SignalsReceiver` makes through `transmitterTransport` when built with `relyingParty`: the stream, polls, Add Subject and Remove Subject | the install script registers the `client_credentials` grant and gives the application the roles that authorize `ssf.read` and `ssf.manage` | asked for again when it expires |
| The test user's password | a password | `OIDC_DEMO_USER_PASSWORD` when set, else generated by iya-sts (`credential: "generate"`) | `demo/generated/<user>.password` (default `oidc-demo-user.password`), 0600; only its path is printed | signing the test user in to try the demo | set at `users/create` (or `users/set-password` when the user exists and `OIDC_DEMO_USER_PASSWORD` is set) | set `OIDC_DEMO_USER_PASSWORD` and re-run the script, or change it in iya-sts |
| The live runs' second user's password | a password | `OIDC_DEMO_DENIED_PASSWORD` when set, else generated by `scripts/live_iya_sts.py` (`secrets.token_urlsafe`) | the live script's environment only; never a file | signing `oidc-demo-denied` (attr1=`not-abc123`) in, by the `--pep` run (handed to its container as `-e NAME`) | `users/create` with `credential: "password"` | a new one on every run (each run starts a fresh iya-sts) |

People's sessions are not credentials of the application: their tokens stay in the relying party's session cache, in memory. `GET /live-status` reports the sign-in and the events, and does not include tokens.

### The embedded PEP's credentials

The PEP (`pep` section; `com.iyasec:iya-pep` is always on the classpath) is a separate identity at iya-sts: it never signs in as the application or as a person. [docs/remote-pep.md](docs/remote-pep.md#credentials) has the detail.

| Credential | Type / algorithm | Made or issued by | Where it lives | Used for | How iya-sts learns of it | Rotation |
|---|---|---|---|---|---|---|
| The service account | an account with no password (`credential: "none"`, `serviceAccount: true`) in the `remote-peps` group | the install script (`--pep`; name `pep-oidc-demo`, `--pep-name`) | iya-sts's directory; `pep.name` in the configuration | the identity the PEP's tokens are issued to | `users/create` and `groups/add-member` | — |
| The PEP's key | EC P-256 (ES256) | made locally with the host's `openssl` (`genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256`); only a certificate request leaves the machine | `pep.assertionKey: "demo/generated/pep-key.pem"`, 0600, never printed, never in the image (Compose mounts `demo/generated`) | an RFC 7523 assertion (`iss` = `sub` = the account, 120 s) for a DPoP-bound access token as the remote-PEP client (`sts-remote-pep`, `pep.clientId`), and every DPoP proof made with that token: registration, heartbeat, the catalogue and policy pulls and the PIP (`xacml:pep`), the decision records (`xacml:pep-audit`), and AuthZEN evaluations in `central` (`authzen:evaluate`) | `issue-pep-credential` certifies the key from its request and binds the PEP to the demo's application | make a new key and certify it (`revokePrevious: true` retires the old one); the PEP reads a changed file again. With the install script: delete the key file and re-run it |

`RelyingParty.create` refuses a PEP key that is the `private_key_jwt` key or the DPoP key (by JWK thumbprint). One key per identity: if the PEP's key were the application's, whoever held the one would hold the other, iya-sts could not tell the PEP's calls from the application's, and a key rotated for one would break the other.

### Install-time only

| Credential | Where it comes from | Used for | Kept? |
|---|---|---|---|
| The management client secret | `ADMIN_API_CLIENT_SECRET` (or `STS_ADMIN_API_CLIENT_SECRET`) in the environment of `scripts/configure_iya_sts.py`; it is iya-sts's `adminApi.clientSecret`, the secret of the seeded `sts-api-client` | a client-credentials token as `sts-api-client` (HTTP Basic), scope `admin:read admin:write`, resource `<realm>/admin-api`, for every `/admin-api` call the script makes | never: not written to a file, not printed, not in the plan `--dry-run` shows |
| The security token | minted from the same secret, scope `admin:read admin:security`, only when a test user is set up, and used for one call: `policies/define-person-attribute`, which defines the realm's custom attribute `attr1` (a Security Administrator's change; iya-sts seeds `sts-api-client` in `SECURITY_ADMIN`). Every other call carries the `admin:read admin:write` token | defining `attr1` for `/attribute-protected`; where the client is not a Security Administrator the call is refused, the script says so and carries on | never |

The demo never sees it. The live script passes it to the containers it starts as `-e NAME`.

### Trust material

- **`tlsCa`** (`generated/idp-ca.pem`, relative to `demo/`) is iya-sts's TLS listener chain (leaf, TLS Issuing CA, Intermediate, Root), saved by the install script (`scripts/trust_chain.py`) from `GET /tls/server-certificate`, or the handshake's chain. The fetch itself is not verified (trust on first use): compare the anchor's SHA-256 the script prints with the Root CA on iya-sts's Server configuration, PKI page. It is public, and the only file of `demo/generated` the image carries.
- **What it verifies:** the library's TLS connections to iya-sts (discovery, token, UserInfo, JWKS, PAR, and the Shared Signals transmitter). The library adds every certificate in the file to the JDK's default trust store. The PEP's connections use the section's own `tlsCa` when it names one. When the section omits `tlsCa` and this library's `tlsCa` is a PEM block (`-----BEGIN`), that PEM is passed through. A path in the library's `tlsCa` is not copied; name `pep.tlsCa`, or put the PEM in `tlsCa`. The install script uses the same chain for its own `/admin-api` calls once it has saved it.
- **Signatures:** ID tokens are verified against the provider's JWKS (`jwks_uri`, fetched over that TLS), in the algorithms `idTokenSigningAlgs` allows; Shared Signals SETs against the transmitter's JWKS. The PEP's pulls arrive over TLS on its own DPoP-bound token.

### Development and product iya-sts

What changes for these credentials with iya-sts's mode (its `docs/v1.2.0/configuration.md` and `remote-pep.md`):
- **The listener's Root.** In development mode iya-sts's listener certificate chains to a service Root regenerated on every start, so `tlsCa` goes stale at each iya-sts restart: run the install script (or `python3 scripts/trust_chain.py --config demo/oidc.json`) again and rebuild the image. `demo/entrypoint.sh` refreshes it at start unless `TLS_CA_REFRESH=0`.
- **The management client secret.** Unless `adminApi.clientSecret` is set before iya-sts starts, the seeded `sts-api-client`'s secret is minted at every start and cannot be read back; in product mode that setting is the way into `/admin-api`. The live script sets it on the container it starts.
- **`remote-peps`.** Development mode seeds the group with a member, `cn=remote-pep-1`; product mode seeds it empty and does not create that account. The install script makes and adds the demo's own account either way.
- **The test user.** Product mode requires a second factor of everybody unless `authn.allowOptionalSecondFactor` is on, so the test user is asked to enrol one at its first sign-in. The test user and its password file are for trying the demo, not for a deployment.

## Layout

| Path | What it is |
|---|---|
| `library/` | The library, `com.iyasec:oidc-caep-risc`, nothing else in its jar. `RelyingParty`, `ClientAuth`, `IdToken`, `Discovery`, `Config`, `ssf/` in `library/src/main/java/com/iyasec/oidc`; JUnit 5 ports of the Node relying-party and Shared Signals tests in `library/src/test/java`. |
| `demo/` | The demo module, never published: `com.iyasec.oidc.demo.Demo`, config `demo/oidc.json`. |
| `scripts/configure_iya_sts.py` | Registers the confidential client on iya-sts with `id_token_signed_response_alg` RS256. `--pep central\|local` also sets up the embedded PEP and writes its `pep` section. The Java repo runs this Python registrar. Loopback redirects follow the running container's `PORT`, then the shell `PORT`. |
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

### The demo with its embedded PEP

One command sets iya-sts up for the demo's PEP and writes its `pep` section (iya-sts with #2026–#2028; `ADMIN_API_CLIENT_SECRET` set as for the plain install):

```sh
python3 scripts/configure_iya_sts.py --pep local     # a bare --pep is local; or --pep central
docker compose up --build
```

Signed in, the home page links Attribute-protected and Order 42. `GET /attribute-protected` is `Access.of("read", "attribute-protected", "attr1")`. `GET /orders/<id>` is `read` on resource type `order`; any other method is `write`. Each is 401 (`Sign in first`) when signed out. With a PEP, the status is `decision.httpStatus()`: 200 and the permitted page, or 403 and `Not allowed`. With no relying party or no `pep` section the page is 403, `Not allowed`, and the library's `decide` is not called. `GET /live-status` includes `pep` from `pep.status()` when a PEP was built. The JDK demo has no Policy enforcement tab.

`python3 scripts/live_iya_sts.py --pep` runs the same checks against a live iya-sts, in `central` and then with `OIDC_CONFIG=/app/demo/oidc.pep-local.json`. The PEP key is mounted at `/app/demo/generated/pep-key.pem` and is not copied into the image.
