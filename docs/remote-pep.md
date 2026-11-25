# Using the iya-sts Remote PEP

This library can ask iya-sts's authorization policy whether a signed-in person (a `RelyingParty.Login`) may do something to a resource in your application, through an embedded **Remote PEP** (Policy Enforcement Point). The PEP itself is the shared [`iya-pep`](https://github.com/rcbj/iya-pep-java) package (`com.iyasec:iya-pep`); this library builds it from your configuration, turns its OpenID Connect sign-in into the PEP's subject, and hands it policy-change events from its Shared Signals stream. The design is [iya-sts #1206](https://github.com/rcbj/iya-sts/issues/1206).

The PEP never permits by default. A decision is a permit or it is not, and anything that is not a permit (a deny, no policy held yet, iya-sts unreachable or answering badly, an engine fault) must be treated as a refusal. `Decision.httpStatus()` is 200 for a permit and 403 otherwise, never a 5xx a client might retry into a different answer. `Decision.isPermit()` is the same split. `pep.decide` never throws.

## Choosing a mode

| | `central` | `local` |
|---|---|---|
| Who decides | iya-sts, per request (`POST /access/v1/evaluation`) | this process, with the PEP's own XACML engine |
| Dependency | `com.iyasec:iya-pep` (always on; there is no feature flag) | the same package |
| Latency | one HTTPS round trip per decision | none after the first pull |
| When iya-sts is down | every decision is a refusal, and a Permit cache (if on) is emptied | decisions continue with the policies held |
| Policy changes | at once | on the `pep-policies-changed` event, or the next poll |
| Decision records | written by iya-sts | sent by the PEP to iya-sts's audit log |

Pick `central` when decisions are infrequent or must reflect a change immediately, and `local` when decisions are on a hot path or must survive a short outage. Both modes give the same answer for the same request: `local` maps the request through the realm's catalogue exactly as iya-sts does, and its engine is held to iya-sts's conformance corpus.

## Before you start: set up iya-sts

You need an iya-sts release with embedded-PEP support (iya-sts #2026, #2027 and #2028). The steps below use the management API; `$API` is `https://<host>/realm/<realm>/admin-api` (or `https://<host>/admin-api` for the default realm) and `$TOKEN` a token for it with write access. Every step has a console equivalent, named after it.

```bash
api() { curl -s -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -d "$2" "$API/$1"; }
```

### 1. Register the application

Register the OpenID Connect client in iya-sts as usual; `scripts/configure_iya_sts.py` does it for the demo. Note its identifier: it is the `application` the PEP is bound to (`clientId` by default).

For the demo, `python3 scripts/configure_iya_sts.py --pep local` (a bare `--pep` is `local` too) or `--pep central` does steps 1 to 6 in one run and writes the `pep` section: see *The demo*. The steps below are what it does, for your own application.

### 2. Create the PEP's service account

The PEP signs in as a service account of its own, never as a person or as the application:

```bash
api users/create '{"username":"pep-orders","invent":false,
  "credential":"none","serviceAccount":true,"owners":["admin-write"],
  "attributes":{"cn":"pep-orders","displayName":"pep-orders"}}'
api groups/add-member '{"group":"remote-peps","member":"pep-orders"}'
```

Console: **Users → New user** (tick **Service account**), then the `remote-peps` group's **Add member**.

The demo's account is `pep-oidc-demo` unless `--pep-name` names another.

### 3. Make the PEP's key, certify it and bind the PEP

Generate the key where the application runs. Only the certificate request leaves the machine. The install script does this with the host's `openssl` and never prints the key:

```bash
umask 077
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out pep-key.pem
chmod 0600 pep-key.pem
openssl req -new -key pep-key.pem -subj /CN=pep-orders -out pep-key.csr
api xacml/issue-pep-credential "$(jq -n --rawfile csr pep-key.csr \
  '{name: "pep-orders", csr: $csr, application: "<application id>"}')"
```

`application` binds the PEP to the application in the same call (`POST /admin-api/xacml/set-pep-application` does it on its own). An EC P-256 key is preferred; RSA of 2048 bits or more is accepted. **The key must be the PEP's own**: `RelyingParty.create` refuses a configuration where the thumbprint equals the `private_key_jwt` key (`privateKey`) or the live DPoP key. The messages are `pep.assertionKey is the private_key_jwt key; the PEP needs a key of its own` and `pep.assertionKey is the DPoP key; the PEP needs a key of its own`.

The demo writes the key at `demo/generated/pep-key.pem` and sets `assertionKey` to `demo/generated/pep-key.pem` (read from the process working directory, `/app` in the image). Compose mounts `demo/generated`. The image does not contain the key.

Console: **Protocols → XACML → Remote PEPs**, **Certify the key**, then the PEP's Overview, **Embedded in an application**.

### 4. Declare the claims your policy reads

The PEP sends a subject's claims only through the realm's AuthZEN attribute catalogue: a claim with no catalogue row is not sent (iya-sts would refuse the whole request). Add one row per claim your policy uses, on **Protocols → XACML → AuthZEN** or with `POST /admin-api/xacml/authzen/set-attribute`. For example, to make `acr` available as `urn:example:acr`:

```bash
api xacml/authzen/set-attribute '{"object":"subject","property":"acr","attributeId":"urn:example:acr"}'
```

which is the row

| `object` | `property` | `attributeId` |
|---|---|---|
| `subject` | `acr` | `urn:example:acr` |

The same applies to resource properties, action properties and context members you put on an `Access`. iya-sts's [AuthZEN page](https://rcbj.github.io/iya-sts/v1.2.0/authzen.html), *The realm's conversion rules*, describes the rows. The install script writes that `subject.acr` row.

### 5. Write the policy

The policy that decides is the application's own fine-grained authorization policy when the application enforces fine-grained authorization, and otherwise the realm's root policy. A `local` PEP is sent that policy and everything it references, and nothing else. The subject's id arrives as XACML's `subject-id`, the action's name as `action-id` and the resource's id as `resource-id`; anything else comes through the catalogue rows of step 4, or from iya-sts's PIP for attributes on the person's directory entry. The resource's type arrives as `urn:sts:xacml:authzen:resource-type`.

For an application that enforces no fine-grained authorization, a root that permits `read` on an `order` when the person's `acr` arrived, and denies everything else, can be written in ALFA (the console's **Policies** tab does the same):

```bash
api xacml/import-alfa "$(jq -n --arg alfa '
namespace orders {
    attribute act { category = actionCat
        id = "urn:oasis:names:tc:xacml:1.0:action:action-id" type = string }
    attribute rtype { category = resourceCat
        id = "urn:sts:xacml:authzen:resource-type" type = string }
    attribute acr { category = subjectCat id = "urn:example:acr" type = string }
    policy ordersRoot {
        id = "urn:example:orders"
        apply firstApplicable
        rule readOrder {
            permit
            target clause act == "read"
            target clause rtype == "order"
            condition integerGreaterThan(stringBagSize(acr), 0)
        }
        rule otherwise { deny }
    }
}' '{name: "orders", alfa: $alfa}')"
api xacml/set-root '{"name":"orders"}'
```

The demo's application enforces its own policy (`urn:example:pepdemo-orders`), so the realm's root is left alone. That policy permits `read` on an `order` when `acr` arrived, permits `read` on `attribute-protected` when the person's directory attribute `attr1` is `abc123`, and denies everything else. The script rewrites it only while the PolicyId is its own.

Every change to the policy a `local` PEP holds is sent as `pep-policies-changed` (step 6).

### 6. (`local` with signals) let the event through

If the application's entry restricts its Shared Signals streams with `ssfAllowedEvents`, add `urn:iya:sts:secevent:event-type:pep-policies-changed` to it. Otherwise the PEP doesn't hear of a change until its fallback poll, and the application's page in the console warns about it. The install script adds the event only when that list is already restricted.

## The dependency

There is no feature flag. `library/pom.xml` depends on `com.iyasec:iya-pep:0.1.0`. Do not add it to the demo module: the shaded jar takes it transitively.

```xml
<dependency>
  <groupId>com.iyasec</groupId>
  <artifactId>iya-pep</artifactId>
  <version>0.1.0</version>
</dependency>
```

The package is not on Maven Central yet. The image's test stage and its build stage clone `https://github.com/rcbj/iya-pep-java.git` branch `develop` and install it before `mvn`. A build fails until that branch is pushed. Do not merge this library's PEP work to `main` until `iya-pep` is on Maven Central. `develop` may be ahead of `main`.

A section that names no `mode` is `local`. Both modes are in the one dependency.

## Configure

Add a `pep` section to `oidc.json`. The PEP is off unless it is present.

```json
"pep": {
  "name": "pep-orders",
  "mode": "local",
  "assertionKey": "pep-key.pem"
}
```

| Member | Default here | What it is |
|---|---|---|
| `name` | required | The PEP's service account (step 2). |
| `mode` | `local` | `local` (the PEP pulls its application's policies, caches them in memory and decides in process) or `central` (it asks iya-sts for every decision). |
| `assertionKey` | required | The PEP's private key in PEM: a path; a relative one is read from the process's working directory. The file is re-read when it changes. |
| `pdpUrl` | the provider's `issuer` (the realm prefix included) | iya-sts, with `/realm/<id>` for a realm. Passed to `PepConfig.fromJson` as the default; it is not written into the section. |
| `application` | `clientId` | The application the PEP is bound to (step 3). Passed the same way. |
| `clientId` | `sts-remote-pep` | The client the PEP's assertion is presented through. |
| `signals` | the library's `signals` (on unless `signals` is false) | Whether a signal stream hands over policy-change events. Applied when the section omits it. With it on, the PEP starts as `down` until the receiver reports the stream. |
| `pollIntervalMs` | 15000 | `local`: the poll period while the stream does not carry the event (no stream, `down` or `excluded`). |
| `fallbackPollMs` | 300000 | `local`: the poll period while the stream carries the event (`requested`), in case one is lost. |
| `heartbeatIntervalMs` | 30000 | How often the PEP reports to iya-sts. |
| `permitCacheMs` | 0 (off) | `central` only: reuse a permit for this long, at most 60000. The policy-change event clears it, and so does a failed evaluation or a failed heartbeat: no cached permit is served until iya-sts answers an evaluation again. |
| `supportedObligations` | `[]` | The obligation types your application discharges (see *Obligations*). |
| `decisionRecords` | `true` | `local`: send each decision to iya-sts's audit log. |
| `tlsCa` | the library's `tlsCa` when that value is a PEM block | PEM trust anchors for iya-sts's TLS. A path in the library's `tlsCa` is not copied; name `pep.tlsCa`, or put the PEM in `tlsCa`. |
| `timeoutMs` | 10000 | Per request to iya-sts. |

An unknown member is refused, so a misspelt one doesn't quietly fall back to a default. `RelyingParty.create` and `RelyingParty.fromFile` build the PEP and call `start()`.

## Decide

```java
RelyingParty rp = RelyingParty.fromFile("oidc.json"); // registers the PEP and, in local mode, pulls

// After RelyingParty.Login login = rp.complete(query, request, sessionId):
Access access = Access.of("read", "order", orderId);
Map<String, Object> userinfo = rp.userinfo(token.accessToken, token.tokenType, login.subject);
Decision decision = rp.decide(login, access, userinfo);
int status = decision.httpStatus(); // 200 for a permit, 403 for anything else
if (decision.isPermit()) {
    // serve
}
```

Answer the request with `httpStatus()` rather than your own mapping, so a failure can never become anything but a 403. Whether the person is signed in at all (a 401) is your question, asked before the PEP's. The demo's order and attribute routes do that.

`Access.of(action, resourceType, resourceId)` carries the AuthZEN action and resource. Add resource properties, action properties or context members as your policy needs them, each declared in the catalogue (step 4). The PEP always sets the application on the context to the bound application, whatever you put there.

**The subject** comes from the sign-in, never from a request header. `PepWiring.subjectWithUserinfo` builds it:

- **id:** the `username` claim when it is a non-empty string, else `preferredUsername`, else `sub`. iya-sts's PIP resolves a username, a DN or a certificate subject. Every ID token iya-sts issues carries `username`; `preferred_username` is a `profile` claim, there only when that scope was granted.
- **properties:** every ID token claim (`acr`, `amr`, `auth_time`, `email`, …). Fetched userinfo claims are laid over them. `decide(login, access)` passes an empty userinfo map. The demo fetches userinfo once per session and passes that map; a failed fetch still decides, on the ID token claims alone.

Only the properties the catalogue declares are sent.

**Signed out.** This library's session store holds `SessionTokens`, not the sign-in's claims, so there is no `decideSession`. Ask whether the person is signed in (the demo answers 401, heading `Sign in first`) before you call `decide`. A session the receiver has ended is gone from the demo's own session, and the next request is that 401.

**Without a `pep` section**, `rp.pep()` is null and `decide` throws `OidcError` with code `config` and message `no pep section is configured`. Nothing permits by default. The demo answers 403, heading `Not allowed`, body `No decision could be asked for.`, and does not call `decide` and does not construct a `Decision`.

**`pep.decide` never throws.** No policy held, a service that can't be reached or answers badly, or an engine fault is a non-permit (`httpStatus()` 403).

### Obligations

A permit can carry obligations, which your application must carry out before it grants the access (for example a `step-up` to a stronger `acr`). The PEP only hands you obligations of types you list in `supportedObligations`. A permit carrying any other obligation is turned into a refusal, so an obligation is never silently dropped. Advice can be ignored; `central` carries it only while the realm's `authzen.returnReasons` is on.

```json
"pep": { "name": "pep-orders", "assertionKey": "pep-key.pem", "supportedObligations": ["step-up"] }
```

This library's `Decision` exposes `isPermit()` and `httpStatus()`. Read the obligation list from the decision the PEP returned before you serve a permit.

## Receive policy-change events

In `local` mode, and in `central` mode with a Permit cache (`permitCacheMs` greater than 0), the PEP wants to hear when the policies change. Build the receiver with `relyingParty`, as you already do for authorized transmitter calls; it finds the PEP there.

```java
SignalsReceiver receiver = SignalsReceiver.builder(transmitter, onEnd)
        .relyingParty(rp)
        .tls(rp.tls())
        .transport(rp.transmitterTransport("ssf.manage"))
        .build();
receiver.start();
```

The constructor then asks its stream for `urn:iya:sts:secevent:event-type:pep-policies-changed` (`Pep.POLICIES_CHANGED_EVENT`), verifies each Security Event Token like every other one, and hands the payload to `pep.onPolicyEvent`. A stream that already exists (made before the `pep` section was added, or while the PEP was `central` with no Permit cache) is updated with `PATCH` to ask for the event too; if the transmitter refuses, the receiver still starts, the refusal goes to `onError` (or the log), and the PEP's heartbeat reports the event as `excluded`. The event is only a hint: the PEP pulls with its own credential and never trusts the event's contents. An event naming another PEP is ignored.

The same receiver tells the transmitter whom this application follows: Add Subject when `track` follows a person's sign-in (`iss_sub` with the transmitter's issuer and the session's `person`, else `email`), Remove Subject when their last one here ends (`ssf.addSubjects`, default on; a non-boolean is refused). A stream that names subjects carries only events about them, and `pep-policies-changed` is about the application, so when the PEP wants events the receiver also adds the application (`{"format": "opaque", "id": <application>}`) at `start` and never removes it. Without that, policy changes would reach a `local` PEP only by its poll once someone had signed in. A refused subject call goes to `onError` and never fails the sign-in.

The receiver keeps the PEP's view of the stream current: `setEventStream` is `REQUESTED` (or `EXCLUDED`, when neither delivered nor requested events name it) when the receiver starts and after each poll that succeeds, and `DOWN` after a poll that fails and once `stop()` is called. A `local` PEP polls at `pollIntervalMs` while the stream is not `requested`, so a change still arrives while the stream cannot carry it, and the heartbeat reports the state.

## Credentials

The PEP has credentials of its own, separate from the application's (the client secret or `private_key_jwt` key, the DPoP key, the Shared Signals token; see the README's *Credentials*).

### The embedded PEP's credentials

- **The service account** (step 2): an account with no password, a member of `remote-peps`, named by `pep.name`. Tokens are issued to it, never to a person or the application.
- **The key** (step 3): EC P-256 preferred (RSA 2048 or more accepted), made where the application runs; only its certificate request is sent. `issue-pep-credential` certifies it for the account and binds the PEP to the application. `pep.assertionKey` names its file (a path); keep the file 0600 and out of images.
- **What it authenticates:** the PEP signs an RFC 7523 assertion (`iss` = `sub` = the account, `aud` the token endpoint, 120 s, a fresh `jti`) and gets a DPoP-bound access token as the remote-PEP client (`pep.clientId`, default `sts-remote-pep`), one per audience: `xacml:pep` (registration, heartbeat, the catalogue and policy pulls, the PIP), `xacml:pep-audit` (the decision records `local` ships), and `authzen:evaluate` (`central`'s evaluations). The same key signs every DPoP proof, so each token is bound to it. No token, key or proof is logged.
- **Its own key:** `RelyingParty.create` refuses an assertion key that is the `private_key_jwt` key or the DPoP key, by JWK thumbprint (`SigningKey.pemThumbprint` and `Dpop.thumbprint()`). Shared, the holder of one credential would hold the other, iya-sts could not tell the PEP's calls from the application's, and rotating one would break the other.
- **Rotation:** see *Operate it* (a new key, `issue-pep-credential` with `revokePrevious: true`, then the file replaced; the PEP reads it again).

## Operate it

- **Health.** `rp.pep().status()` reports whether the PEP is registered and running, whether it holds a policy (its `syncToken` is the policy version, not a credential), its decision counters and its current problems. It holds no secret, so it is safe on a health page. The demo puts it on `GET /live-status` under `pep`.
- **In the console.** The PEP appears under **Protocols → XACML → Remote PEPs** with its kind (`embedded`), application, mode, protocol version and whether its stream carries policy-change events. The application's page lists the PEPs bound to it.
- **Rotating the key.** Generate a new key, certify it with `issue-pep-credential` (add `revokePrevious: true` to retire the old one), and replace the file. The PEP reads a changed `assertionKey` again. The tokens bound to the old key are dropped. With the install script: delete `demo/generated/pep-key.pem` and run it again.
- **Audit.** In `local` mode each decision becomes an audit row in iya-sts (`authzen.remote.decision`). In `central` mode iya-sts records its own.
- **Shutdown.** Stop the receiver, then `rp.pep().stop()`. The demo's shutdown hook does that.

## Troubleshooting

| What you see | Likely cause |
|---|---|
| Every decision refused, `status()` says not registered, a problem mentioning 403 | The PEP's entry has no binding, or is bound to another application (iya-sts `STS-XACML-0338`, `0339`). Repeat step 3 with the right `application`. |
| A refusal and a problem naming the token endpoint (`invalid_grant`) | The key isn't certified for this account, or the account isn't in `remote-peps` (steps 2 and 3). |
| A refusal with "no policy is held yet" (`local`) | The first pull hasn't succeeded. Check `status()`'s last error: a 403 on the policy pull (`STS-XACML-0343`) means the PEP isn't registered as an embedded `local` PEP bound to that application. |
| A registration refused with 400 (`STS-XACML-0340`) | The iya-sts release doesn't support this PEP's protocol version. Upgrade iya-sts or this library. |
| A refusal saying the evaluation was refused (`local`: "refused (STS-AUTHZEN-0004)"; `central`: "the service refused the evaluation: invalid_request …") | A resource, action or context property you sent has no catalogue row (step 4). Subject claims without a row are dropped, not refused. |
| A refusal although the policy should permit | The policy reads a claim that has no catalogue row, so it never arrives (step 4). Or a permit carried an obligation type missing from `supportedObligations`. |
| Policy changes take minutes to apply (`local`) | The stream is `requested` but the event never arrives, so only the `fallbackPollMs` poll brings the change. The stream doesn't carry the event: check the console's *policy-change events* column, `ssfAllowedEvents` (step 6), and `onError` for a refused stream update. |
| The configuration is refused for the assertion key | It is one of this library's own keys. The PEP needs a key of its own. |

## The demo

The JDK demo protects two routes when `demo/oidc.json` has a `pep` section.

`GET /orders/<id>` (the id is the rest of the path, nonempty, no slash) is `Access.of("read", "order", id)`. Any other method on that path is `write`, which the demo's policy denies. `GET /attribute-protected` is `Access.of("read", "attribute-protected", "attr1")`: the application's policy permits it when the person's directory attribute `attr1` is `abc123`, which the PEP asks iya-sts's PIP for (it is not in the ID token).

Each route is 401, heading `Sign in first`, when there is no local session. With a PEP, the status is `decision.httpStatus()`: 200 on a permit (an order's heading is `Order <id>` and the page says the PEP permitted the action; the attribute page's heading is `Allowed` and it says your attr1 is abc123), and 403, heading `Not allowed`, on a deny and on any PEP failure. With no relying party, or no `pep` section, the page is 403, heading `Not allowed`, body `No decision could be asked for.`, and `decide` is not called. Signed in, the home page links Attribute-protected and Order 42. `GET /live-status` carries `pep.status()` under `pep`. The JDK demo has no Policy enforcement tab.

Set it up in one command:

```sh
python3 scripts/configure_iya_sts.py --pep local    # a bare --pep is local; or --pep central
docker compose up --build
```

This registers the client as without `--pep`, then does steps 2 to 6 (a bare `--pep` is `local`):

- the service account `pep-oidc-demo` (`--pep-name`) in `remote-peps`;
- a P-256 key in `demo/generated/pep-key.pem`, made with `openssl` (0600, never printed, mounted by Compose and never in the image), certified from its own request with the PEP bound to the demo's application;
- the catalogue row `subject.acr` → `urn:example:acr`;
- the demo application's own policy, which it then enforces, so the realm's root is untouched: `read` on an `order` when the sign-in carried an `acr`, `read` on `attribute-protected` when the person's `attr1` is `abc123`, and a deny for everything else;
- `pep-policies-changed` added to `ssfAllowedEvents` only if the application restricts it.

It writes the `pep` section (`name`, `mode`, `assertionKey`) into `demo/oidc.json` and keeps any other members already there. With a test user (the default, `oidc-demo-user`; with or without `--pep`), the script also gives that user `attr1=abc123`. Defining the realm's custom attribute `attr1` is a Security Administrator's change, so the script makes that one call with a second token carrying `admin:security` (iya-sts seeds the management client in `SECURITY_ADMIN`); if that is refused and the value cannot be set, it says what to add on the console and carries on.

Run it again, for example with `--pep central` to switch modes: the account and the key are kept and the binding is set again. The application's policy is rewritten to the script's current version while its PolicyId is the script's own (`urn:example:pepdemo-orders`); a policy under any other PolicyId is left as it is, so your edits survive. `--dry-run` prints every call and does not make a key. The image copies `demo/oidc.json` in when it is built, so rebuild after the script writes the section (`docker compose up --build`); Compose mounts `demo/generated`, which holds the PEP's key.

`python3 scripts/live_iya_sts.py --pep` (or `LIVE_PEP=1`) needs an iya-sts with #2026–#2028. It runs the install script with `--pep central`, writes `demo/oidc.pep-local.json` with `mode` `local`, and starts the demo with the client secret and `demo/generated/pep-key.pem` mounted read-only. `GET /orders/42` must be 200 and `POST /orders/42` 403. A second user, `oidc-demo-denied`, gets `attr1=not-abc123` (password `OIDC_DEMO_DENIED_PASSWORD`, never printed, its own HTTP client). `GET /attribute-protected` must be 200, heading `Allowed`, for `oidc-demo-user` and 403, heading `Not allowed`, for the denied user, whose `GET /orders/42` is 200. After the credential-change and session-revoked checks, the demo starts again with `OIDC_CONFIG=/app/demo/oidc.pep-local.json`, both users sign in, the same checks run, then the application's policy is replaced with one that denies `read`. Within `PEP_FLIP_TIMEOUT` seconds (30) the GET must be 403 and `pep-policies-changed` must have arrived on `GET /live-status` (the fallback poll stays at its 300 s default, so the change came by the event). The result's `pep` object holds the central and local checks. Defaults stay 18544 and 18644.

## See also

- [`iya-pep`'s README](https://github.com/rcbj/iya-pep-java#readme): the package's own API and every configuration member.
- iya-sts's [Remote PEP page](https://rcbj.github.io/iya-sts/v1.2.0/remote-pep.html), *An embedded PEP's application*: the service's side of the binding, registration and the scoped pull.
- iya-sts's [CAEP events page](https://rcbj.github.io/iya-sts/v1.2.0/caep-events.html): the `pep-policies-changed` event.
- The README's [Credentials](../README.md#credentials): every credential this library and the demo use.
