# oidc-caep-risc

A confidential OpenID Connect relying party for a traditional Java application, and a CAEP and RISC receiver on one Shared Signals poll stream. Authorization Code with PKCE (S256) is required. Client authentication is `client_secret_basic`, `client_secret_post`, or `private_key_jwt`. A public client (`tokenEndpointAuthMethod` `"none"`) is refused. JSON Web Signature uses the JDK (JCA). This library does not wrap an OpenID Connect framework.

JSON configuration keys are the same names the Node library `oidc-caep-risc-nodejs` reads. `signals` omitted or `true` keeps CAEP and RISC on. `signals: false` does not start the receiver, does not require transmitter metadata, and drops `ssf.read` and `ssf.manage` from the scope list after the default scopes are applied. `DEFAULT_SCOPES` still names those two scopes. The shipped demo leaves `signals` on (the key is omitted).

The license is MIT. `develop` and `main` are the same commit. Publishing to Maven Central is not set up yet.

## Usage

Java 17. Group `com.iyasec`, artifact `oidc-caep-risc`, version `0.1.0`.

```java
RelyingParty rp = RelyingParty.fromFile("oidc.json");
RelyingParty.Transaction request = rp.authorize();
// redirect the browser to request.url; keep state, nonce, and codeVerifier
RelyingParty.Login who = rp.complete(query, request);
```

Tokens stay in this process. Keep the transaction until the browser returns.

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
| `src/main/java/com/iyasec/oidc` | The library. `RelyingParty`, `ClientAuth`, `IdToken`, `Discovery`, `Config`, `ssf/`. |
| `src/test/java` | JUnit 5 ports of the Node relying-party and Shared Signals tests. |
| `demo` | `com.iyasec.oidc.demo.Demo`. Config is `demo/oidc.json`. |
| `scripts/configure_iya_sts.py` | Registers the confidential client on iya-sts. The Java repo runs this Python registrar. Loopback redirects follow the running container's `PORT`, then the shell `PORT`. |
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

`GET /healthz` returns `ok`. `GET /` is the page. `GET /login` starts `authorize` and redirects. `GET /callback` completes the code exchange. `POST /logout` signs the local session out. `GET /live-status` is JSON for the sign-in and the Shared Signals events this process has accepted. It does not include tokens.

`docker-compose.yml` sets `network_mode: host`. The image sets `ENV PORT=3000`. The health check calls `http://127.0.0.1:${PORT}/healthz`. The running container's `PORT` wins over the shell's when `scripts/configure_iya_sts.py` registers the application.

Demo JSON uses `file:` and the configuration's own placeholders. It does not contain a generated secret or key.
