// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.oidc;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.Executors;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The confidential client against a stub OpenID Provider. */
class RelyingPartyTest {
    static final String CLIENT = "oidc-caep-risc-demo";
    static final String SECRET = "test-secret";
    static final String SCOPES = "openid profile email offline_access ssf.read ssf.manage";
    static KeyPair providerKeys;
    static KeyPair clientKeys;
    static Map<String, Object> providerJwk;
    static String clientPem;
    static HttpServer server;
    static Stub stub;

    @BeforeAll
    static void up() throws Exception {
        providerKeys = rsa();
        clientKeys = rsa();
        providerJwk = jwk((RSAPublicKey) providerKeys.getPublic(), "op");
        clientPem = pem((RSAPrivateKey) clientKeys.getPrivate());
        stub = new Stub();
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", RelyingPartyTest::handle);
        server.setExecutor(Executors.newCachedThreadPool());
        server.start();
        stub.url = "http://127.0.0.1:" + server.getAddress().getPort();
    }

    @AfterAll
    static void down() {
        if (server != null) server.stop(0);
    }

    @AfterEach
    void resetStub() {
        stub.reset();
    }

    @Test
    void defaultScopesAndAtHash() throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest("abc".getBytes(StandardCharsets.UTF_8));
        assertEquals(SCOPES, Discovery.DEFAULT_SCOPES);
        assertEquals(Codec.b64UrlEncode(java.util.Arrays.copyOf(digest, digest.length / 2)), IdToken.hashClaim("abc", "RS256"));
    }

    @Test
    void signsInWithPkce() throws Exception {
        RelyingParty rp = RelyingParty.create(config());
        Signed signed = signIn(rp);
        assertEquals("user-1", signed.login.subject);
        assertEquals("user-1@example.com", signed.login.email);
        assertEquals("sid-1", signed.login.sid);
        assertEquals(stub.url, signed.login.issuer);
        assertEquals("user-1", signed.login.preferredUsername);
        assertNotNull(signed.login.refreshToken);
        assertTrue(signed.request.url.contains("code_challenge="));
        assertTrue(signed.request.url.contains("code_challenge_method=S256"));
        assertFalse(signed.request.url.contains("client_secret"));
        assertEquals("user-1", rp.userinfo(signed.login.accessToken, signed.login.subject).get("sub"));
        String end = rp.endSessionUrl(signed.login.idToken, "bye");
        assertTrue(end.contains("/end-session"));
        assertTrue(end.contains("id_token_hint="));
        assertTrue(end.contains("client_id="));
    }

    @Test
    void refusesACallbackThatIsNotThisSignIn() throws Exception {
        RelyingParty rp = RelyingParty.create(config());
        RelyingParty.Transaction request = rp.authorize();
        Map<String, String> query = query(manual(request.url).location);
        RelyingParty.Transaction wrongState = copy(request);
        wrongState.state = "nope";
        assertMessage("state", () -> rp.complete(query, wrongState));
        RelyingParty.Transaction wrongNonce = copy(request);
        wrongNonce.nonce = "nope";
        assertMessage("nonce", () -> rp.complete(query, wrongNonce));
        query.put("iss", "https://elsewhere.example");
        assertMessage("iss mismatch", () -> rp.complete(query, request));
        query.put("iss", stub.url);
        query.put("access_token", "should-not-be-here");
        assertMessage("access_token", () -> rp.complete(query, request));
    }

    @Test
    void acceptsACodeOnce() throws Exception {
        RelyingParty rp = RelyingParty.create(config());
        Signed signed = signIn(rp);
        assertEquals("user-1", signed.login.subject);
        assertMessage("already used", () -> rp.complete(signed.query, signed.request));
    }

    @Test
    void refusesBadTokens() throws Exception {
        RelyingParty rp = RelyingParty.create(config());
        Map<String, Object> wrongConfig = config();
        wrongConfig.put("clientSecret", "nope");
        RelyingParty wrong = RelyingParty.create(wrongConfig);
        RelyingParty.Transaction request = wrong.authorize();
        Map<String, String> query = query(manual(request.url).location);
        OidcError invalid = assertThrows(OidcError.class, () -> wrong.complete(query, request));
        assertEquals("invalid_client", invalid.oauthError);

        stub.corrupt = true;
        assertMessage("signature", () -> signIn(rp));
        stub.aud = "other-client";
        assertMessage("audience|aud", () -> signIn(rp));
        stub.exp = System.currentTimeMillis() / 1000 - 3600;
        assertMessage("exp|timestamp|old|iat", () -> signIn(rp));
        stub.badAtHash = true;
        assertMessage("at_hash", () -> signIn(rp));
    }

    @Test
    void refreshAndClientCredentials() throws Exception {
        RelyingParty rp = RelyingParty.create(config());
        RelyingParty.Login login = signIn(rp).login;
        RelyingParty.Login refreshed = rp.refresh(login.refreshToken, login);
        assertEquals(login.subject, refreshed.subject);
        assertNotEquals(login.accessToken, refreshed.accessToken);
        assertEquals("cc-token", rp.clientCredentials("ssf.manage").accessToken);
        assertEquals("cc-token", rp.clientCredentials("ssf.manage").accessToken);
    }

    @Test
    void par() throws Exception {
        stub.par = true;
        try {
            RelyingParty rp = RelyingParty.create(config());
            Signed signed = signIn(rp);
            assertTrue(signed.request.url.contains("request_uri="));
            assertFalse(signed.request.url.contains("code_challenge="));
            assertEquals("user-1", signed.login.subject);
        } finally {
            stub.par = false;
        }
    }

    @Test
    void postAndPrivateKeyJwt() throws Exception {
        Map<String, Object> posted = config();
        posted.put("tokenEndpointAuthMethod", "client_secret_post");
        assertEquals("user-1", signIn(RelyingParty.create(posted)).login.subject);
        Map<String, Object> jwt = config();
        jwt.put("tokenEndpointAuthMethod", "private_key_jwt");
        jwt.remove("clientSecret");
        jwt.put("privateKeyPem", clientPem);
        assertEquals("user-1", signIn(RelyingParty.create(jwt)).login.subject);
    }

    @Test
    void readsConfigurationFileNames() throws Exception {
        Path directory = Files.createTempDirectory("oidc-config-");
        Files.writeString(directory.resolve("secret"), "from-file\n");
        Config.environment = name -> "OIDC_TEST_SECRET".equals(name) ? "from-env" : System.getenv(name);
        try {
            Map<String, Object> file = baseFile();
            file.put("clientSecret", "env:OIDC_TEST_SECRET");
            file.put("scopes", List.of(SCOPES.split(" ")));
            Map<String, Object> env = Config.resolveConfig(file, directory.toString());
            assertEquals(CLIENT, env.get("clientId"));
            assertEquals("from-env", env.get("clientSecret"));
            assertEquals("https://localhost:8081", env.get("issuer"));
            assertEquals(SCOPES, env.get("scopes"));
            assertEquals("client_secret_basic", env.get("tokenEndpointAuthMethod"));
            Map<String, Object> fromFile = new LinkedHashMap<>(file);
            fromFile.put("clientSecret", "file:secret");
            assertEquals("from-file", Config.resolveConfig(fromFile, directory.toString()).get("clientSecret"));
            String chain = "-----BEGIN CERTIFICATE-----\nchain\n-----END CERTIFICATE-----\n";
            Files.writeString(directory.resolve("ca.pem"), chain);
            assertEquals(chain, Config.resolveConfig(with(file, "tlsCa", "ca.pem"), directory.toString()).get("tlsCa"));
            assertEquals(chain, Config.resolveConfig(with(file, "tlsCa", "file:ca.pem"), directory.toString()).get("tlsCa"));
            assertEquals(chain.strip(), Config.resolveConfig(with(file, "tlsCa", chain), directory.toString()).get("tlsCa"));
            Config.environment = name -> "OIDC_TEST_CA".equals(name) ? chain : "OIDC_TEST_SECRET".equals(name) ? "from-env" : System.getenv(name);
            assertEquals(chain, Config.resolveConfig(with(file, "tlsCa", "env:OIDC_TEST_CA"), directory.toString()).get("tlsCa"));
            Config.environment = name -> "OIDC_TEST_SECRET".equals(name) ? "from-env" : System.getenv(name);
            assertNull(Config.resolveConfig(with(file, "tlsCa", "env:OIDC_TEST_CA"), directory.toString()).get("tlsCa"));
            assertNull(Config.resolveConfig(with(file, "tlsCa", "missing.pem"), directory.toString()).get("tlsCa"));
            assertMessage("public client", () -> Config.resolveConfig(with(file, "tokenEndpointAuthMethod", "none"), directory.toString()));
            assertMessage("openid", () -> Config.resolveConfig(with(file, "scopes", "profile email"), directory.toString()));
        } finally {
            Config.environment = System::getenv;
        }
    }

    @Test
    void signalsFlag() {
        Map<String, Object> file = baseFile();
        file.put("clientSecret", "secret");
        Map<String, Object> ssf = new LinkedHashMap<>();
        ssf.put("transmitter", "https://localhost:8081/");
        ssf.put("pollIntervalMs", 3000);
        file.put("ssf", ssf);
        Map<String, Object> omitted = Config.resolveConfig(file, ".");
        assertEquals(SCOPES, omitted.get("scopes"));
        assertFalse(omitted.containsKey("signals"));
        assertEquals(Map.of("transmitter", "https://localhost:8081", "pollIntervalMs", 3000), omitted.get("ssf"));
        Map<String, Object> explicit = new LinkedHashMap<>(file);
        explicit.put("signals", true);
        explicit.put("scopes", SCOPES);
        Map<String, Object> on = Config.resolveConfig(explicit, ".");
        assertEquals(SCOPES, on.get("scopes"));
        assertFalse(on.containsKey("signals"));
        assertEquals(omitted.get("ssf"), on.get("ssf"));

        Map<String, Object> listedDoc = new LinkedHashMap<>(file);
        listedDoc.put("signals", false);
        listedDoc.put("scopes", SCOPES);
        listedDoc.put("ssf", Map.of("transmitter", "not-a-url"));
        Map<String, Object> listed = Config.resolveConfig(listedDoc, ".");
        assertEquals(Boolean.FALSE, listed.get("signals"));
        assertNull(listed.get("ssf"));
        assertEquals("openid profile email offline_access", listed.get("scopes"));
        assertFalse(List.of(String.valueOf(listed.get("scopes")).split(" ")).contains("ssf.read"));
        assertFalse(List.of(String.valueOf(listed.get("scopes")).split(" ")).contains("ssf.manage"));

        Map<String, Object> defaultsDoc = new LinkedHashMap<>(file);
        defaultsDoc.put("signals", false);
        Map<String, Object> defaults = Config.resolveConfig(defaultsDoc, ".");
        assertEquals(Boolean.FALSE, defaults.get("signals"));
        assertNull(defaults.get("ssf"));
        assertEquals("openid profile email offline_access", defaults.get("scopes"));
        assertTrue(List.of(String.valueOf(defaults.get("scopes")).split(" ")).contains("openid"));

        assertMessage("openid", () -> Config.resolveConfig(with(with(file, "signals", false), "scopes", "ssf.read ssf.manage"), "."));
        OidcError bad = assertThrows(OidcError.class, () -> Config.resolveConfig(with(file, "signals", "no"), "."));
        assertEquals("config", bad.code);
        assertEquals("signals must be true or false", bad.getMessage());
    }

    // Issue #25, point 1: DPoP.

    @Test
    void dpopAutoBindsEveryTokenAndResourceRequest() throws Exception {
        stub.dpopAlgs = List.of("ES256", "RS256");
        RelyingParty rp = RelyingParty.create(config());
        assertTrue(rp.usesDpop());
        Signed signed = signIn(rp);
        String jkt = rp.dpop().thumbprint();
        assertEquals(jkt, query(signed.request.url).get("dpop_jkt"));
        assertEquals(jkt, stub.lastAuthorize.get("dpop_jkt"));
        assertEquals("DPoP", signed.login.tokenType);
        Map<String, Object> code = proof("/token", "authorization_code");
        assertEquals(jkt, code.get("jkt"));
        assertEquals("POST", code.get("htm"));
        assertEquals(stub.url + "/token", code.get("htu"));
        assertFalse(code.containsKey("ath"));

        assertEquals("user-1", rp.userinfo(signed.login.accessToken, signed.login.subject).get("sub"));
        Map<String, Object> userinfo = proof("/userinfo", null);
        assertEquals("GET", userinfo.get("htm"));
        assertEquals(jkt, userinfo.get("jkt"));
        assertEquals(Codec.b64UrlEncode(MessageDigest.getInstance("SHA-256").digest(signed.login.accessToken.getBytes(StandardCharsets.US_ASCII))), userinfo.get("ath"));

        RelyingParty.Login refreshed = rp.refresh(signed.login.refreshToken, signed.login);
        assertEquals("DPoP", refreshed.tokenType);
        assertEquals(jkt, proof("/token", "refresh_token").get("jkt"));

        RelyingParty.Credentials cc = rp.clientCredentials("ssf.manage");
        assertEquals("DPoP", cc.tokenType);
        assertEquals(jkt, proof("/token", "client_credentials").get("jkt"));
    }

    @Test
    void dpopProofOnThePushedRequestAndJktInItsBody() throws Exception {
        stub.dpopAlgs = List.of("ES256");
        stub.par = true;
        RelyingParty rp = RelyingParty.create(config());
        Signed signed = signIn(rp);
        assertTrue(signed.request.url.contains("request_uri="));
        assertFalse(signed.request.url.contains("dpop_jkt"));
        assertEquals(rp.dpop().thumbprint(), stub.lastAuthorize.get("dpop_jkt"));
        Map<String, Object> pushed = proof("/par", null);
        assertEquals(stub.url + "/par", pushed.get("htu"));
        assertEquals(rp.dpop().thumbprint(), pushed.get("jkt"));
        assertEquals("DPoP", signed.login.tokenType);
    }

    @Test
    void dpopNonceFromTheAuthorizationServerIsRetriedOnceAndRemembered() throws Exception {
        stub.dpopAlgs = List.of("ES256");
        stub.asNonce = "as-nonce-1";
        RelyingParty rp = RelyingParty.create(config());
        Signed signed = signIn(rp);
        assertEquals("user-1", signed.login.subject);
        assertEquals(1, stub.nonceChallenges.get());
        rp.clientCredentials("ssf.manage");
        assertEquals(1, stub.nonceChallenges.get(), "the remembered nonce went on the next proof");
        assertEquals("as-nonce-1", proof("/token", "client_credentials").get("nonce"));
        assertEquals("as-nonce-1", rp.dpop().nonce(stub.url + "/anything?x=1"));
    }

    @Test
    void dpopNonceFromAResourceServerIsRetriedOnce() throws Exception {
        stub.dpopAlgs = List.of("ES256");
        RelyingParty rp = RelyingParty.create(config());
        Signed signed = signIn(rp);
        stub.rsNonce = "rs-nonce-1";
        assertEquals("user-1", rp.userinfo(signed.login.accessToken, signed.login.subject).get("sub"));
        assertEquals(1, stub.nonceChallenges.get());
        assertEquals("rs-nonce-1", proof("/userinfo", null).get("nonce"));
        rp.userinfo(signed.login.accessToken, signed.login.subject);
        assertEquals(1, stub.nonceChallenges.get());
    }

    @Test
    void dpopOnEveryCallToTheTransmitter() throws Exception {
        stub.dpopAlgs = List.of("ES256");
        stub.rsNonce = "ssf-nonce";
        RelyingParty rp = RelyingParty.create(config());
        Http.Result answer = rp.transmitterTransport("ssf.manage")
                .send("POST", stub.url + "/resource?stream=s1", Map.of("accept", "application/json"), "{}".getBytes(StandardCharsets.UTF_8));
        assertEquals(200, answer.status());
        Map<String, Object> sent = proof("/resource", null);
        assertEquals(stub.url + "/resource", sent.get("htu"), "htu has no query or fragment");
        assertEquals("POST", sent.get("htm"));
        assertEquals("ssf-nonce", sent.get("nonce"));
        assertEquals(Codec.b64UrlEncode(MessageDigest.getInstance("SHA-256").digest("cc-token".getBytes(StandardCharsets.US_ASCII))), sent.get("ath"));
        assertEquals("stream=s1", sent.get("query"));
        assertEquals(1, stub.nonceChallenges.get());
        assertEquals(stub.url + "/a/b", Dpop.htu(stub.url + "/a/b?x=1#f"));
    }

    @Test
    void dpopModes() throws Exception {
        assertMessage("dpop_signing_alg_values_supported", () -> RelyingParty.create(with(config(), "dpop", "always")));
        stub.dpopAlgs = List.of("PS256");
        assertMessage("ES256", () -> RelyingParty.create(with(config(), "dpop", "always")));
        RelyingParty skipped = RelyingParty.create(config());
        assertFalse(skipped.usesDpop());
        Signed bearer = signIn(skipped);
        assertEquals("Bearer", bearer.login.tokenType);
        assertFalse(bearer.request.url.contains("dpop_jkt"));
        assertTrue(stub.proofs.isEmpty());

        stub.dpopAlgs = List.of("ES256");
        RelyingParty never = RelyingParty.create(with(config(), "dpop", "never"));
        assertFalse(never.usesDpop());
        assertEquals("Bearer", signIn(never).login.tokenType);
        assertTrue(stub.proofs.isEmpty());
        assertTrue(RelyingParty.create(with(config(), "dpop", "always")).usesDpop());
        assertMessage("dpop must be", () -> RelyingParty.create(with(config(), "dpop", "sometimes")));
    }

    @Test
    void tokenTypeMustMatchWhetherAProofWasSent() throws Exception {
        stub.dpopAlgs = List.of("ES256");
        stub.forceTokenType = "Bearer";
        RelyingParty bound = RelyingParty.create(config());
        assertMessage("not DPoP", () -> signIn(bound));
        stub.forceTokenType = "DPoP";
        RelyingParty plain = RelyingParty.create(with(config(), "dpop", "never"));
        assertMessage("not Bearer", () -> signIn(plain));
        stub.forceTokenType = "dpop";
        assertEquals("dpop", signIn(bound).login.tokenType);
    }

    @Test
    void dpopKeyFromPem() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new java.security.spec.ECGenParameterSpec("secp256r1"));
        KeyPair pair = generator.generateKeyPair();
        byte[] pkcs8 = pair.getPrivate().getEncoded();
        java.security.interfaces.ECPublicKey expected = (java.security.interfaces.ECPublicKey) pair.getPublic();
        String x = Codec.b64UrlEncode(fixed(expected.getW().getAffineX()));
        String y = Codec.b64UrlEncode(fixed(expected.getW().getAffineY()));
        Dpop fromPkcs8 = Dpop.fromPem(pemOf("PRIVATE KEY", pkcs8));
        assertEquals(x, fromPkcs8.jwk().get("x"));
        assertEquals(y, fromPkcs8.jwk().get("y"));
        assertEquals(thumbprint(fromPkcs8.jwk()), fromPkcs8.thumbprint());
        // The SEC 1 key is the OCTET STRING at the end of the PKCS#8 encoding.
        int at = (pkcs8[1] & 0x80) != 0 ? 2 + (pkcs8[1] & 0x7f) : 2;
        at += 3;
        at += 2 + (pkcs8[at + 1] & 0xff);
        assertEquals(0x04, pkcs8[at]);
        int length = pkcs8[at + 1] & 0xff;
        int start = at + 2;
        if ((length & 0x80) != 0) {
            int octets = length & 0x7f;
            length = 0;
            for (int i = 0; i < octets; i++) length = (length << 8) | (pkcs8[at + 2 + i] & 0xff);
            start = at + 2 + octets;
        }
        byte[] sec1 = java.util.Arrays.copyOfRange(pkcs8, start, start + length);
        assertEquals(x, Dpop.fromPem(pemOf("EC PRIVATE KEY", sec1)).jwk().get("x"));

        stub.dpopAlgs = List.of("ES256");
        RelyingParty rp = RelyingParty.create(with(config(), "dpopKey", pemOf("PRIVATE KEY", pkcs8)));
        assertEquals(fromPkcs8.thumbprint(), rp.dpop().thumbprint());
        signIn(rp);
        assertEquals(fromPkcs8.thumbprint(), proof("/token", "authorization_code").get("jkt"));

        KeyPairGenerator p384 = KeyPairGenerator.getInstance("EC");
        p384.initialize(new java.security.spec.ECGenParameterSpec("secp384r1"));
        assertMessage("P-256", () -> Dpop.fromPem(pemOf("PRIVATE KEY", p384.generateKeyPair().getPrivate().getEncoded())));
    }

    // Point 2: acr.

    @Test
    void acrIsEnforcedWhenRequested() throws Exception {
        RelyingParty rp = RelyingParty.create(config());
        RelyingParty.AuthorizeOptions options = new RelyingParty.AuthorizeOptions();
        options.acrValues = "urn:acr:mfa urn:acr:hw";
        stub.acr = "urn:acr:hw";
        RelyingParty.Transaction request = rp.authorize(options);
        assertEquals("urn:acr:mfa urn:acr:hw", request.acrValues);
        assertEquals("urn:acr:mfa urn:acr:hw", query(request.url).get("acr_values"));
        RelyingParty.Login login = rp.complete(query(manual(request.url).location), request);
        assertEquals("urn:acr:hw", login.acr);
        RelyingParty.Login refreshed = rp.refresh(login.refreshToken, login);
        assertNull(refreshed.claims.get("acr"), "the refresh path does not re-check acr");

        stub.acr = "urn:acr:pwd";
        RelyingParty.Transaction other = rp.authorize(options);
        assertMessage("not one of the requested", () -> rp.complete(query(manual(other.url).location), other));
        stub.acr = null;
        RelyingParty.Transaction none = rp.authorize(options);
        assertMessage("has no acr", () -> rp.complete(query(manual(none.url).location), none));

        RelyingParty configured = RelyingParty.create(with(config(), "acrValues", List.of("urn:acr:mfa")));
        RelyingParty.Transaction fromSetting = configured.authorize();
        assertEquals("urn:acr:mfa", fromSetting.acrValues);
        assertMessage("has no acr", () -> configured.complete(query(manual(fromSetting.url).location), fromSetting));
        stub.acr = "urn:acr:mfa";
        assertEquals("urn:acr:mfa", signIn(configured).login.acr);
        stub.acr = null;
        assertEquals("user-1", signIn(rp).login.subject);
    }

    // Point 3: PAR required by the provider.

    @Test
    void parRequiredByTheProvider() throws Exception {
        stub.par = true;
        stub.requirePar = true;
        assertMessage("requires pushed", () -> RelyingParty.create(with(config(), "par", "never")));
        Signed signed = signIn(RelyingParty.create(config()));
        assertTrue(signed.request.url.contains("request_uri="));
        stub.par = false;
        assertMessage("no pushed authorization endpoint", () -> RelyingParty.create(config()));
    }

    // Point 4: RS256 by default.

    @Test
    void idTokenAlgorithmsDefaultToRs256() throws Exception {
        assertEquals(List.of("RS256"), Config.normalize(config()).get("idTokenSigningAlgs"));
        assertEquals(List.of("RS256"), Discovery.idTokenAlgorithms(List.of("ES256", "RS256", "PS256"), null, List.of("RS256")));
        assertEquals(List.of("ES256"), Discovery.idTokenAlgorithms(List.of("ES256", "RS256"), null, List.of("ES256", "PS256")));
        assertEquals(List.of("PS256"), Discovery.idTokenAlgorithms(List.of("PS256"), "PS256", List.of("RS256")));
        assertMessage("advertises no ID token algorithm", () -> Discovery.idTokenAlgorithms(List.of("ES256"), null, List.of("RS256")));
        assertMessage("never accepted", () -> RelyingParty.create(with(config(), "idTokenSigningAlgs", List.of("RS256", "none"))));
        assertMessage("none", () -> RelyingParty.create(with(config(), "idTokenSignedResponseAlg", "none")));

        stub.advertisedAlgs = List.of("ES256");
        assertMessage("advertises no ID token algorithm", () -> RelyingParty.create(config()));

        stub.advertisedAlgs = List.of("RS256", "HS256");
        stub.idAlg = "HS256";
        RelyingParty strict = RelyingParty.create(config());
        assertMessage("does not accept", () -> signIn(strict));
        stub.idAlg = "HS256";
        RelyingParty named = RelyingParty.create(with(config(), "idTokenSigningAlgs", List.of("RS256", "HS256")));
        assertEquals("user-1", signIn(named).login.subject);
        stub.idAlg = "RS256";
        assertEquals("user-1", signIn(named).login.subject);
    }

    // Point 5: typ and at_hash required.

    @Test
    void typAndAtHashAreRequired() throws Exception {
        RelyingParty rp = RelyingParty.create(config());
        stub.typ = null;
        assertMessage("no typ", () -> signIn(rp));
        stub.typ = "at+jwt";
        assertMessage("typ", () -> signIn(rp));
        stub.typ = "application/JWT";
        assertEquals("user-1", signIn(rp).login.subject);
        stub.noAtHash = true;
        assertMessage("no at_hash", () -> signIn(rp));

        RelyingParty relaxed = RelyingParty.create(with(config(), "requireIdTokenTypAndAtHash", false));
        stub.typ = null;
        stub.noAtHash = true;
        assertEquals("user-1", signIn(relaxed).login.subject);
        stub.badAtHash = true;
        assertMessage("at_hash", () -> signIn(relaxed));
        stub.typ = "logout+jwt";
        assertMessage("typ", () -> signIn(relaxed));
        assertMessage("true or false", () -> RelyingParty.create(with(config(), "requireIdTokenTypAndAtHash", "no")));
    }

    // Point 6: the same checks when the client is created directly.

    @Test
    void directCreationGetsTheDefaultsAndTheRedirectRule() throws Exception {
        Map<String, Object> bare = config();
        for (String key : List.of("par", "clockToleranceSec", "maxIdTokenAgeSec", "privateKeyAlg")) bare.remove(key);
        RelyingParty rp = RelyingParty.create(bare);
        assertEquals("auto", rp.config().get("par"));
        assertEquals("auto", rp.config().get("dpop"));
        assertEquals(30, rp.config().get("clockToleranceSec"));
        assertEquals(600, rp.config().get("maxIdTokenAgeSec"));
        assertEquals(List.of("RS256"), rp.config().get("idTokenSigningAlgs"));
        assertEquals(Boolean.TRUE, rp.config().get("requireIdTokenTypAndAtHash"));

        Map<String, Object> file = baseFile();
        file.put("clientSecret", "s");
        Map<String, Object> resolved = Config.resolveConfig(file, ".");
        for (String key : List.of("par", "dpop", "clockToleranceSec", "maxIdTokenAgeSec", "idTokenSigningAlgs", "requireIdTokenTypAndAtHash")) {
            assertEquals(rp.config().get(key), resolved.get(key), key);
        }

        for (String good : List.of("https://app.example/cb", "http://localhost:3000/cb", "http://127.0.0.1/cb", "http://[::1]:8080/cb")) {
            assertEquals(good, RelyingParty.create(with(config(), "redirectUri", good)).config().get("redirectUri"));
        }
        assertMessage("https, or http on loopback", () -> RelyingParty.create(with(config(), "redirectUri", "http://app.example/cb")));
        assertMessage("https, or http on loopback", () -> Config.resolveConfig(with(with(file, "redirectUri", "http://app.example/cb"), "allowInsecure", true), "."));
        assertMessage("redirectUri is required", () -> RelyingParty.create(with(config(), "redirectUri", "")));
        assertMessage("https, or http on loopback", () -> RelyingParty.create(with(config(), "postLogoutRedirectUri", "http://app.example/")));
        RelyingParty.AuthorizeOptions override = new RelyingParty.AuthorizeOptions();
        override.redirectUri = "http://evil.example/cb";
        assertMessage("https, or http on loopback", () -> rp.authorize(override));
        override.redirectUri = "https://app.example/other";
        assertEquals("https://app.example/other", query(rp.authorize(override).url).get("redirect_uri"));

        stub.iatFuture = true;
        assertMessage("iat is in the future", () -> signIn(rp));
    }

    // Point 7: the per-session cache.

    @Test
    void sessionCacheReturnsTheCachedTokenThenRefreshes() throws Exception {
        stub.dpopAlgs = List.of("ES256");
        RelyingParty rp = RelyingParty.create(config());
        RelyingParty.Transaction request = rp.authorize();
        RelyingParty.Login login = rp.complete(query(manual(request.url).location), request, "app-session-1");
        assertEquals("app-session-1", login.sessionId);
        RelyingParty.Credentials cached = rp.sessionAccessToken("app-session-1");
        assertEquals(login.accessToken, cached.accessToken);
        assertEquals("DPoP", cached.tokenType);
        int before = stub.proofs.size();
        assertEquals(login.accessToken, rp.sessionAccessToken("app-session-1").accessToken);
        assertEquals(before, stub.proofs.size(), "no token request while the cached token has time left");

        stub.expiresIn = 20;
        Signed shortLived = signIn(rp);
        assertNotNull(shortLived.login.sessionId, "complete() without an identifier returns a handle");
        assertNotNull(rp.sessionStore().get(shortLived.login.sessionId));
        RelyingParty.Credentials renewed = rp.sessionAccessToken(shortLived.login.sessionId);
        assertNotEquals(shortLived.login.accessToken, renewed.accessToken);
        assertEquals(rp.dpop().thumbprint(), proof("/token", "refresh_token").get("jkt"));
        assertEquals(renewed.accessToken, rp.sessionStore().get(shortLived.login.sessionId).accessToken());
        assertEquals("user-1", rp.userinfo(renewed.accessToken, renewed.tokenType, "user-1").get("sub"));

        stub.refresh.clear();
        OidcError refused = assertThrows(OidcError.class, () -> rp.sessionAccessToken(shortLived.login.sessionId));
        assertEquals("session", refused.code);
        assertNull(rp.sessionStore().get(shortLived.login.sessionId), "a failed refresh removes the entry");

        rp.removeSession("app-session-1");
        assertMessage("no tokens", () -> rp.sessionAccessToken("app-session-1"));
    }

    @Test
    void sessionStoreCanBeReplaced() throws Exception {
        Map<String, SessionTokens> shared = new ConcurrentHashMap<>();
        List<String> calls = new CopyOnWriteArrayList<>();
        SessionStore store = new SessionStore() {
            public SessionTokens get(String id) {
                calls.add("get " + id);
                return shared.get(id);
            }

            public void put(String id, SessionTokens tokens) {
                calls.add("put " + id);
                shared.put(id, tokens);
            }

            public void remove(String id) {
                calls.add("remove " + id);
                shared.remove(id);
            }
        };
        RelyingParty rp = RelyingParty.create(config()).sessionStore(store);
        RelyingParty.Transaction request = rp.authorize();
        RelyingParty.Login login = rp.complete(query(manual(request.url).location), request, "s-9");
        assertEquals("user-1", shared.get("s-9").subject());
        assertEquals("Bearer", shared.get("s-9").tokenType());
        assertEquals(login.accessToken, rp.sessionAccessToken("s-9").accessToken);
        rp.removeSession("s-9");
        assertTrue(shared.isEmpty());
        assertEquals(List.of("put s-9", "get s-9", "remove s-9"), calls);
    }

    static Map<String, Object> proof(String path, String grant) {
        Map<String, Object> found = null;
        for (Map<String, Object> item : stub.proofs) {
            if (path.equals(item.get("path")) && (grant == null || grant.equals(item.get("grant")))) found = item;
        }
        assertNotNull(found, "no DPoP proof reached " + path + (grant == null ? "" : " (" + grant + ")"));
        return found;
    }

    static byte[] fixed(BigInteger value) {
        byte[] raw = value.toByteArray();
        byte[] out = new byte[32];
        int copy = Math.min(raw.length, 32);
        System.arraycopy(raw, raw.length - copy, out, 32 - copy, copy);
        return out;
    }

    static String pemOf(String label, byte[] der) {
        return "-----BEGIN " + label + "-----\n" + Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.UTF_8)).encodeToString(der) + "\n-----END " + label + "-----\n";
    }

    static Map<String, Object> config() {
        Map<String, Object> doc = new LinkedHashMap<>();
        doc.put("metadataUrl", stub.url + "/.well-known/openid-configuration");
        doc.put("clientId", CLIENT);
        doc.put("clientSecret", SECRET);
        doc.put("tokenEndpointAuthMethod", "client_secret_basic");
        doc.put("redirectUri", "http://127.0.0.1/callback");
        doc.put("postLogoutRedirectUri", "http://127.0.0.1/");
        doc.put("scopes", SCOPES);
        doc.put("privateKeyAlg", "RS256");
        doc.put("par", "auto");
        doc.put("clockToleranceSec", 30);
        doc.put("maxIdTokenAgeSec", 600);
        doc.put("allowInsecure", true);
        return doc;
    }

    static Map<String, Object> baseFile() {
        Map<String, Object> file = new LinkedHashMap<>();
        file.put("metadataUrl", "https://localhost:8081/.well-known/openid-configuration");
        file.put("client_id", CLIENT);
        file.put("clientSecret", "env:OIDC_TEST_SECRET");
        file.put("redirectUri", "http://localhost:3000/callback");
        return file;
    }

    static Map<String, Object> with(Map<String, Object> file, String key, Object value) {
        Map<String, Object> copy = new LinkedHashMap<>(file);
        copy.put(key, value);
        return copy;
    }

    static Signed signIn(RelyingParty rp) throws Exception {
        RelyingParty.Transaction request = rp.authorize();
        Manual manual = manual(request.url);
        assertNotNull(manual.location, "the provider did not redirect (" + manual.status + ")");
        Map<String, String> query = query(manual.location);
        return new Signed(request, query, rp.complete(query, request));
    }

    static Manual manual(String url) throws Exception {
        HttpClient client = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).connectTimeout(Duration.ofSeconds(10)).build();
        HttpResponse<Void> response = client.send(HttpRequest.newBuilder(URI.create(url)).timeout(Duration.ofSeconds(10)).GET().build(), HttpResponse.BodyHandlers.discarding());
        return new Manual(response.statusCode(), response.headers().firstValue("location").orElse(null));
    }

    static Map<String, String> query(String location) {
        Map<String, String> out = new LinkedHashMap<>();
        String raw = URI.create(location).getRawQuery();
        if (raw == null) return out;
        for (String part : raw.split("&")) {
            int at = part.indexOf('=');
            String key = URLDecoder.decode(at < 0 ? part : part.substring(0, at), StandardCharsets.UTF_8);
            String value = URLDecoder.decode(at < 0 ? "" : part.substring(at + 1), StandardCharsets.UTF_8);
            out.put(key, value);
        }
        return out;
    }

    static RelyingParty.Transaction copy(RelyingParty.Transaction request) {
        RelyingParty.Transaction copy = new RelyingParty.Transaction();
        copy.url = request.url;
        copy.state = request.state;
        copy.nonce = request.nonce;
        copy.codeVerifier = request.codeVerifier;
        copy.redirectUri = request.redirectUri;
        copy.maxAge = request.maxAge;
        copy.expectedSub = request.expectedSub;
        return copy;
    }

    static void assertMessage(String pattern, Throwing call) {
        OidcError err = assertThrows(OidcError.class, call::run);
        assertTrue(Pattern.compile(pattern).matcher(String.valueOf(err.getMessage())).find(), err.getMessage());
    }

    static void handle(HttpExchange exchange) {
        try {
            byte[] raw = exchange.getRequestBody().readAllBytes();
            String text = new String(raw, StandardCharsets.UTF_8);
            String path = exchange.getRequestURI().getPath();
            if ("/.well-known/openid-configuration".equals(path)) {
                json(exchange, 200, metadata());
                return;
            }
            if ("/jwks".equals(path)) {
                json(exchange, 200, Map.of("keys", List.of(providerJwk)));
                return;
            }
            if ("/userinfo".equals(path) || "/resource".equals(path)) {
                String token = presented(exchange, path);
                if (token == null) return;
                if ("/resource".equals(path)) {
                    json(exchange, "cc-token".equals(token) ? 200 : 401, "cc-token".equals(token) ? Map.of("ok", true) : Map.of("error", "invalid_token"));
                    return;
                }
                Map<String, Object> claims = stub.access.get(token);
                json(exchange, claims == null ? 401 : 200, claims == null ? Map.of("error", "invalid_token") : claims);
                return;
            }
            boolean proofSent = false;
            if (("/par".equals(path) || "/token".equals(path)) && "POST".equals(exchange.getRequestMethod())) {
                String proof = header(exchange, "dpop");
                if (!proof.isEmpty()) {
                    proofSent = true;
                    Map<String, Object> checked;
                    try {
                        checked = checkProof(proof, "POST", stub.url + path, null);
                    } catch (Exception err) {
                        json(exchange, 400, Map.of("error", "invalid_dpop_proof", "error_description", String.valueOf(err.getMessage())));
                        return;
                    }
                    checked.put("path", path);
                    checked.put("grant", form(text).getOrDefault("grant_type", ""));
                    stub.proofs.add(checked);
                    if (stub.asNonce != null && !stub.asNonce.equals(checked.get("nonce"))) {
                        stub.nonceChallenges.incrementAndGet();
                        jsonWith(exchange, 400, Map.of("error", "use_dpop_nonce"), Map.of("DPoP-Nonce", stub.asNonce));
                        return;
                    }
                }
            }
            if ("/par".equals(path) && "POST".equals(exchange.getRequestMethod())) {
                if (!authorized(exchange, text)) {
                    json(exchange, 401, Map.of("error", "invalid_client"));
                    return;
                }
                String requestUri = "urn:par:" + Long.toHexString(System.nanoTime());
                stub.pushed.put(requestUri, form(text));
                json(exchange, 201, Map.of("request_uri", requestUri, "expires_in", 60));
                return;
            }
            if ("/authorize".equals(path)) {
                Map<String, String> query = form(exchange.getRequestURI().getRawQuery() == null ? "" : exchange.getRequestURI().getRawQuery());
                String stored = query.get("request_uri");
                Map<String, String> params = stored == null ? query : stub.pushed.get(stored);
                if (params == null) {
                    json(exchange, 400, Map.of("error", "invalid_request"));
                    return;
                }
                stub.lastAuthorize = params;
                String redirect = params.getOrDefault("redirect_uri", "");
                String state = params.getOrDefault("state", "");
                String challenge = params.getOrDefault("code_challenge", "");
                if (!"S256".equals(params.get("code_challenge_method")) || challenge.isEmpty()) {
                    json(exchange, 400, Map.of("error", "invalid_request"));
                    return;
                }
                Map<String, String> row = new LinkedHashMap<>();
                row.put("sub", "user-1");
                row.put("email", "user-1@example.com");
                row.put("sid", "sid-1");
                row.put("nonce", params.getOrDefault("nonce", ""));
                row.put("redirect", redirect);
                row.put("challenge", challenge);
                if (stub.acr != null) row.put("acr", stub.acr);
                String code = Long.toHexString(System.nanoTime());
                stub.codes.put(code, row);
                URI back = URI.create(redirect);
                String location = back.getScheme() + "://" + back.getRawAuthority() + (back.getRawPath() == null || back.getRawPath().isEmpty() ? "/" : back.getRawPath())
                        + "?code=" + URLEncoder.encode(code, StandardCharsets.UTF_8)
                        + "&state=" + URLEncoder.encode(state, StandardCharsets.UTF_8)
                        + "&iss=" + URLEncoder.encode(stub.url, StandardCharsets.UTF_8);
                exchange.getResponseHeaders().set("location", location);
                exchange.sendResponseHeaders(302, 0);
                exchange.close();
                return;
            }
            if ("/token".equals(path) && "POST".equals(exchange.getRequestMethod())) {
                if (!authorized(exchange, text)) {
                    json(exchange, 401, Map.of("error", "invalid_client", "error_description", "client authentication failed"));
                    return;
                }
                Map<String, String> params = form(text);
                String grant = params.getOrDefault("grant_type", "");
                String tokenType = stub.forceTokenType != null ? stub.forceTokenType : proofSent ? "DPoP" : "Bearer";
                if ("client_credentials".equals(grant)) {
                    json(exchange, 200, Map.of("access_token", "cc-token", "token_type", tokenType, "expires_in", 120, "scope", params.getOrDefault("scope", "")));
                    return;
                }
                if ("refresh_token".equals(grant)) {
                    Map<String, String> row = stub.refresh.get(params.getOrDefault("refresh_token", ""));
                    if (row == null) {
                        json(exchange, 400, Map.of("error", "invalid_grant"));
                        return;
                    }
                    Map<String, Object> minted = tokenFor(row, tokenType);
                    Map<String, Object> claims = new LinkedHashMap<>(stub.access.get(minted.get("access_token")));
                    claims.remove("nonce");
                    claims.remove("acr");
                    minted.put("id_token", idToken(claims, false));
                    json(exchange, 200, minted);
                    return;
                }
                String code = params.getOrDefault("code", "");
                Map<String, String> row = stub.codes.get(code);
                if (row == null || !row.get("redirect").equals(params.get("redirect_uri"))) {
                    json(exchange, 400, Map.of("error", "invalid_grant"));
                    return;
                }
                String verifier = params.getOrDefault("code_verifier", "");
                String got = Codec.b64UrlEncode(MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(StandardCharsets.UTF_8)));
                if (!got.equals(row.get("challenge"))) {
                    json(exchange, 400, Map.of("error", "invalid_grant", "error_description", "pkce"));
                    return;
                }
                stub.codes.remove(code);
                json(exchange, 200, tokenFor(row, tokenType));
                return;
            }
            json(exchange, 404, Map.of("error", "not_found"));
        } catch (Exception err) {
            try {
                byte[] body = err.toString().getBytes(StandardCharsets.UTF_8);
                exchange.sendResponseHeaders(500, body.length);
                exchange.getResponseBody().write(body);
                exchange.close();
            } catch (Exception ignored) {
                // The client sees a closed connection.
            }
        }
    }

    static Map<String, Object> metadata() {
        Map<String, Object> doc = new LinkedHashMap<>();
        doc.put("issuer", stub.url);
        doc.put("authorization_endpoint", stub.url + "/authorize");
        doc.put("token_endpoint", stub.url + "/token");
        doc.put("jwks_uri", stub.url + "/jwks");
        doc.put("userinfo_endpoint", stub.url + "/userinfo");
        doc.put("end_session_endpoint", stub.url + "/end-session");
        doc.put("response_types_supported", List.of("code"));
        doc.put("subject_types_supported", List.of("public"));
        doc.put("id_token_signing_alg_values_supported", stub.advertisedAlgs);
        doc.put("token_endpoint_auth_methods_supported", List.of("client_secret_basic", "client_secret_post", "private_key_jwt"));
        doc.put("code_challenge_methods_supported", List.of("S256"));
        doc.put("authorization_response_iss_parameter_supported", true);
        doc.put("scopes_supported", List.of(SCOPES.split(" ")));
        if (stub.par) doc.put("pushed_authorization_request_endpoint", stub.url + "/par");
        if (stub.requirePar) doc.put("require_pushed_authorization_requests", true);
        if (stub.dpopAlgs != null) doc.put("dpop_signing_alg_values_supported", stub.dpopAlgs);
        return doc;
    }

    static Map<String, Object> tokenFor(Map<String, String> row, String tokenType) throws Exception {
        String access = Long.toHexString(System.nanoTime());
        String refresh = Long.toHexString(System.nanoTime() + 1);
        long now = System.currentTimeMillis() / 1000;
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("iss", stub.url);
        payload.put("sub", row.get("sub"));
        payload.put("aud", stub.aud);
        payload.put("exp", stub.exp != null ? stub.exp : now + 300);
        payload.put("iat", stub.exp != null ? stub.exp : stub.iatFuture ? now + 120 : now);
        if (row.get("acr") != null) payload.put("acr", row.get("acr"));
        payload.put("nonce", row.get("nonce"));
        payload.put("email", row.get("email"));
        payload.put("name", "Demo User");
        payload.put("preferred_username", row.get("sub"));
        payload.put("sid", row.get("sid"));
        if (!stub.noAtHash) payload.put("at_hash", stub.badAtHash ? "aaaa" : IdToken.hashClaim(access, stub.idAlg));
        String token = idToken(payload, stub.corrupt);
        stub.refresh.put(refresh, row);
        stub.access.put(access, payload);
        stub.aud = CLIENT;
        stub.corrupt = false;
        stub.badAtHash = false;
        stub.exp = null;
        stub.noAtHash = false;
        stub.iatFuture = false;
        stub.typ = "JWT";
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("access_token", access);
        out.put("token_type", tokenType);
        out.put("expires_in", stub.expiresIn);
        out.put("refresh_token", refresh);
        out.put("id_token", token);
        out.put("scope", SCOPES);
        return out;
    }

    static String idToken(Map<String, Object> payload, boolean corrupt) throws Exception {
        Map<String, Object> head = new LinkedHashMap<>();
        head.put("alg", stub.idAlg);
        if (!"HS256".equals(stub.idAlg)) head.put("kid", "op");
        if (stub.typ != null) head.put("typ", stub.typ);
        String header = Codec.b64UrlEncode(Jsons.write(head).getBytes(StandardCharsets.UTF_8));
        String body = Codec.b64UrlEncode(Jsons.write(payload).getBytes(StandardCharsets.UTF_8));
        byte[] input = (header + "." + body).getBytes(StandardCharsets.US_ASCII);
        String sig;
        if ("HS256".equals(stub.idAlg)) {
            javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
            mac.init(new javax.crypto.spec.SecretKeySpec(SECRET.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            sig = Codec.b64UrlEncode(mac.doFinal(input));
        } else {
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(providerKeys.getPrivate());
            signature.update(input);
            sig = Codec.b64UrlEncode(signature.sign());
        }
        if (corrupt) sig = ("A".equals(sig.substring(0, 1)) ? "B" : "A") + sig.substring(1);
        return header + "." + body + "." + sig;
    }

    static boolean authorized(HttpExchange exchange, String body) throws Exception {
        String header = header(exchange, "authorization");
        if (header.startsWith("Basic ")) {
            String decoded = new String(Base64.getDecoder().decode(header.substring(6)), StandardCharsets.UTF_8);
            return decoded.equals(CLIENT + ":" + SECRET);
        }
        Map<String, String> params = form(body);
        if (params.containsKey("client_secret")) return CLIENT.equals(params.get("client_id")) && SECRET.equals(params.get("client_secret"));
        String assertion = params.get("client_assertion");
        return assertion != null && !assertion.isEmpty() && clientOk(assertion);
    }

    static boolean clientOk(String assertion) throws Exception {
        String[] parts = assertion.split("\\.", -1);
        if (parts.length != 3) return false;
        Map<String, Object> header = Jsons.map(Jsons.read(new String(Codec.b64UrlDecode(parts[0], "header"), StandardCharsets.UTF_8)));
        Map<String, Object> payload = Jsons.map(Jsons.read(new String(Codec.b64UrlDecode(parts[1], "payload"), StandardCharsets.UTF_8)));
        if (header == null || payload == null || !"RS256".equals(header.get("alg"))) return false;
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(clientKeys.getPublic());
        signature.update((parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII));
        if (!signature.verify(Codec.b64UrlDecode(parts[2], "signature"))) return false;
        Object aud = payload.get("aud");
        List<String> audiences = new ArrayList<>();
        if (aud instanceof List<?> items) for (Object item : items) audiences.add(String.valueOf(item));
        else audiences.add(String.valueOf(aud));
        return CLIENT.equals(payload.get("iss")) && CLIENT.equals(payload.get("sub")) && audiences.contains(stub.url);
    }

    static void json(HttpExchange exchange, int status, Object body) throws Exception {
        jsonWith(exchange, status, body, Map.of());
    }

    static void jsonWith(HttpExchange exchange, int status, Object body, Map<String, String> headers) throws Exception {
        byte[] raw = Jsons.write(body).getBytes(StandardCharsets.UTF_8);
        headers.forEach((name, value) -> exchange.getResponseHeaders().set(name, value));
        exchange.getResponseHeaders().set("content-type", "application/json");
        exchange.sendResponseHeaders(status, raw.length);
        exchange.getResponseBody().write(raw);
        exchange.close();
    }

    static String header(HttpExchange exchange, String name) {
        String value = exchange.getRequestHeaders().getFirst(name);
        return value == null ? "" : value;
    }

    static Map<String, String> form(String text) {
        Map<String, String> out = new LinkedHashMap<>();
        if (text == null || text.isEmpty()) return out;
        for (String part : text.split("&")) {
            int at = part.indexOf('=');
            String key = URLDecoder.decode(at < 0 ? part : part.substring(0, at), StandardCharsets.UTF_8);
            String value = URLDecoder.decode(at < 0 ? "" : part.substring(at + 1), StandardCharsets.UTF_8);
            out.put(key, value);
        }
        return out;
    }

    static KeyPair rsa() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    static Map<String, Object> jwk(RSAPublicKey key, String kid) {
        Map<String, Object> jwk = new LinkedHashMap<>();
        jwk.put("kty", "RSA");
        jwk.put("n", b64(key.getModulus()));
        jwk.put("e", b64(key.getPublicExponent()));
        jwk.put("kid", kid);
        jwk.put("alg", "RS256");
        jwk.put("use", "sig");
        return jwk;
    }

    static String b64(BigInteger number) {
        byte[] raw = number.toByteArray();
        if (raw[0] == 0) raw = java.util.Arrays.copyOfRange(raw, 1, raw.length);
        return Codec.b64UrlEncode(raw);
    }

    static String pem(RSAPrivateKey key) {
        String body = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.UTF_8)).encodeToString(key.getEncoded());
        return "-----BEGIN PRIVATE KEY-----\n" + body + "\n-----END PRIVATE KEY-----\n";
    }

    interface Throwing { void run() throws Exception; }

    record Manual(int status, String location) {}
    record Signed(RelyingParty.Transaction request, Map<String, String> query, RelyingParty.Login login) {}

    /** The access token a resource request presents, after the stub's DPoP checks; null when it already answered. */
    static String presented(HttpExchange exchange, String path) throws Exception {
        String header = header(exchange, "authorization");
        if (header.startsWith("Bearer ")) return header.substring(7).trim();
        if (!header.startsWith("DPoP ")) {
            json(exchange, 401, Map.of("error", "invalid_token"));
            return null;
        }
        String token = header.substring(5).trim();
        Map<String, Object> checked;
        try {
            checked = checkProof(header(exchange, "dpop"), exchange.getRequestMethod(), stub.url + path, token);
        } catch (Exception err) {
            jsonWith(exchange, 401, Map.of("error", "invalid_dpop_proof"), Map.of("WWW-Authenticate", "DPoP error=\"invalid_dpop_proof\""));
            return null;
        }
        checked.put("path", path);
        checked.put("query", exchange.getRequestURI().getRawQuery());
        stub.proofs.add(checked);
        if (stub.rsNonce != null && !stub.rsNonce.equals(checked.get("nonce"))) {
            stub.nonceChallenges.incrementAndGet();
            Map<String, String> headers = new LinkedHashMap<>();
            headers.put("WWW-Authenticate", "DPoP error=\"use_dpop_nonce\", error_description=\"Resource server requires nonce in DPoP proof\"");
            headers.put("DPoP-Nonce", stub.rsNonce);
            jsonWith(exchange, 401, Map.of("error", "use_dpop_nonce"), headers);
            return null;
        }
        return token;
    }

    /** Verifies a DPoP proof the way an authorization or resource server does, and returns its payload with the key's thumbprint as "jkt". */
    static Map<String, Object> checkProof(String proof, String method, String url, String accessToken) throws Exception {
        String[] parts = proof.split("\\.", -1);
        if (parts.length != 3) throw new IllegalArgumentException("not a JWS");
        Map<String, Object> header = Jsons.map(Jsons.read(new String(Codec.b64UrlDecode(parts[0], "h"), StandardCharsets.UTF_8)));
        Map<String, Object> payload = Jsons.map(Jsons.read(new String(Codec.b64UrlDecode(parts[1], "p"), StandardCharsets.UTF_8)));
        if (!"dpop+jwt".equals(header.get("typ"))) throw new IllegalArgumentException("typ");
        if (!"ES256".equals(header.get("alg"))) throw new IllegalArgumentException("alg");
        Map<String, Object> jwk = Jsons.map(header.get("jwk"));
        if (jwk == null || jwk.containsKey("d")) throw new IllegalArgumentException("jwk");
        byte[] input = (parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII);
        if (!JwsCrypto.verify(JwsCrypto.publicKey(jwk), "ES256", input, Codec.b64UrlDecode(parts[2], "s"))) {
            throw new IllegalArgumentException("signature");
        }
        if (!method.equals(payload.get("htm"))) throw new IllegalArgumentException("htm");
        if (!url.equals(payload.get("htu"))) throw new IllegalArgumentException("htu " + payload.get("htu"));
        if (!(payload.get("jti") instanceof String jti) || jti.isEmpty()) throw new IllegalArgumentException("jti");
        long now = System.currentTimeMillis() / 1000;
        if (!(payload.get("iat") instanceof Number iat) || Math.abs(iat.longValue() - now) > 60) throw new IllegalArgumentException("iat");
        if (accessToken != null) {
            String ath = Codec.b64UrlEncode(MessageDigest.getInstance("SHA-256").digest(accessToken.getBytes(StandardCharsets.US_ASCII)));
            if (!ath.equals(payload.get("ath"))) throw new IllegalArgumentException("ath");
        } else if (payload.containsKey("ath")) {
            throw new IllegalArgumentException("ath on a token request");
        }
        Map<String, Object> out = new LinkedHashMap<>(payload);
        out.put("jkt", thumbprint(jwk));
        return out;
    }

    static String thumbprint(Map<String, Object> jwk) throws Exception {
        String canonical = "{\"crv\":\"" + jwk.get("crv") + "\",\"kty\":\"" + jwk.get("kty") + "\",\"x\":\"" + jwk.get("x") + "\",\"y\":\"" + jwk.get("y") + "\"}";
        return Codec.b64UrlEncode(MessageDigest.getInstance("SHA-256").digest(canonical.getBytes(StandardCharsets.UTF_8)));
    }

    static final class Stub {
        volatile String url = "";
        volatile boolean par;
        volatile boolean corrupt;
        volatile String aud = CLIENT;
        volatile Long exp;
        volatile boolean badAtHash;
        volatile boolean noAtHash;
        volatile boolean iatFuture;
        volatile String typ = "JWT";
        volatile String idAlg = "RS256";
        volatile List<String> advertisedAlgs = List.of("RS256");
        volatile boolean requirePar;
        volatile List<String> dpopAlgs;
        volatile String asNonce;
        volatile String rsNonce;
        volatile String forceTokenType;
        volatile String acr;
        volatile int expiresIn = 300;
        volatile Map<String, String> lastAuthorize = Map.of();
        final java.util.concurrent.atomic.AtomicInteger nonceChallenges = new java.util.concurrent.atomic.AtomicInteger();
        final List<Map<String, Object>> proofs = new CopyOnWriteArrayList<>();

        void reset() {
            par = false;
            corrupt = false;
            aud = CLIENT;
            exp = null;
            badAtHash = false;
            noAtHash = false;
            iatFuture = false;
            typ = "JWT";
            idAlg = "RS256";
            advertisedAlgs = List.of("RS256");
            requirePar = false;
            dpopAlgs = null;
            asNonce = null;
            rsNonce = null;
            forceTokenType = null;
            acr = null;
            expiresIn = 300;
            lastAuthorize = Map.of();
            nonceChallenges.set(0);
            proofs.clear();
        }
        final Map<String, Map<String, String>> codes = new ConcurrentHashMap<>();
        final Map<String, Map<String, String>> refresh = new ConcurrentHashMap<>();
        final Map<String, Map<String, Object>> access = new ConcurrentHashMap<>();
        final Map<String, Map<String, String>> pushed = new ConcurrentHashMap<>();
    }
}
