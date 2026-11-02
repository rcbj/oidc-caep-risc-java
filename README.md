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
mvn -B test
```

The tests build an in-process stub provider and a stub transmitter. They do not need a live iya-sts.

## Layout

| Path | What it is |
|---|---|
| `src/main/java/com/iyasec/oidc` | The library. `RelyingParty`, `ClientAuth`, `IdToken`, `Discovery`, `Config`, `ssf/`. |
| `src/test/java` | JUnit 5 ports of the Node relying-party and Shared Signals tests. |
| `demo` | `com.iyasec.oidc.demo.Demo`. Config is `demo/oidc.json`. |
| `scripts/configure_iya_sts.py` | Registers the confidential client on iya-sts. The Java repo runs this Python registrar. Loopback redirects follow the running container's `PORT`, then the shell `PORT`. |
| `Dockerfile`, `docker-compose.yml` | The demo image. Compose uses host networking. |

## Demo

`PORT` defaults to 3000. A loopback redirect and post-logout URL follow `PORT`. Any other host is left as written. An explicit `PUBLIC_URL` or `--public-url` replaces the origin and keeps the path. The default `http://localhost:3000` is not an explicit public URL.

```sh
mvn -q exec:java
```

`GET /healthz` returns `ok`. `GET /` is the page. `GET /login` starts `authorize` and redirects. `GET /callback` completes the code exchange. `POST /logout` signs the local session out.

`docker-compose.yml` sets `network_mode: host`. The image sets `ENV PORT=3000`. The health check calls `http://127.0.0.1:${PORT}/healthz`. The running container's `PORT` wins over the shell's when `scripts/configure_iya_sts.py` registers the application.

Demo JSON uses `file:` and the configuration's own placeholders. It does not contain a generated secret or key.
