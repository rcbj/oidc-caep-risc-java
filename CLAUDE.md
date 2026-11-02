# oidc-caep-risc

A confidential OpenID Connect relying party for a traditional Java application, and a CAEP and RISC receiver on one Shared Signals poll stream. Authorization Code with PKCE (S256) is required. Client authentication is `client_secret_basic`, `client_secret_post`, or `private_key_jwt`. A public client (`none`) is refused.

`signals` defaults to on. `signals: false` turns CAEP and RISC off: the receiver does not start, transmitter metadata is not required, and the authorization request does not include `ssf.read` or `ssf.manage`. `DEFAULT_SCOPES` still names those two scopes. They are removed after that default is applied. The shipped demo omits `signals`, so they stay on.

The license is the MIT License in `LICENSE`. Publishing to Maven Central is not set up yet. `develop` and `main` are the same commit.

Java 17. JSON is Jackson. Signatures are verified with the JDK (`Signature` and `Mac`). Do not wrap Spring Security, the Nimbus OIDC SDK, or Authlib.

## Layout

| Path | What it is |
|---|---|
| `src/main/java/com/iyasec/oidc` | The library. Source is `RelyingParty.java`, `ClientAuth.java`, `IdToken.java`, `Discovery.java`, `ssf/`. |
| `src/test/java` | JUnit 5. A stub provider and a stub transmitter. No live iya-sts. |
| `demo` | `com.iyasec.oidc.demo.Demo` and `demo/public/`. Config is `demo/oidc.json`. |
| `scripts` | `configure_iya_sts.py` registers the confidential client. `trust_chain.py` refreshes the listener CA file named by `tlsCa`. Both are Python, including in this Java repository. |
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

## Errors

`Caught.error` records a caught exception through `java.lang.System.Logger`, including the stack, and the method then throws the `OidcError` it already threw. The caught exception is the cause. `Caught.warn` is the same record when the method recovers and does not throw: a later signing key, a poll retry, a false verification, sign-out cleanup, or a handler that must still acknowledge the Security Event Token. A `catch (OidcError)` that only throws that error again is not logged a second time.

## Tests

```sh
docker build --target test .
```

The `test` stage runs `mvn -B test` in `maven:3.9.9-eclipse-temurin-17`. GitHub Actions uses that command. Do not run Maven on the host. The demo stage packages with `-DskipTests` in its own Maven image.

## Demo

`docker-compose.yml` sets `network_mode: host`. The process binds `PORT`, default 3000. `ENV PORT=3000` in the image keeps an unset value on 3000, and the health check calls `http://127.0.0.1:${PORT}/healthz`.

```sh
docker compose up --build
```

`GET /healthz` returns `ok`. `GET /` is the page. `GET /login` redirects to the provider. `GET /callback` completes the sign-in. `POST /logout` ends the local session.

A loopback redirect follows `PORT` in the running server and in `scripts/configure_iya_sts.py`. Any other host is left as written. An explicit `--public-url` or a non-empty `PUBLIC_URL` replaces the origin and keeps the path. The running container's `PORT` wins over the shell's when the script registers the application. `pollIntervalMs` is a millisecond pause, not a port.

Open `http://127.0.0.1:$PORT` after the provider is up. Do not bind port 3000 while another demo is already using it.
