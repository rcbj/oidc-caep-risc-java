// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.oidc;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterAll;
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
            if ("/userinfo".equals(path)) {
                String header = header(exchange, "authorization");
                String token = header.startsWith("Bearer ") ? header.substring(7).trim() : "";
                Map<String, Object> claims = stub.access.get(token);
                json(exchange, claims == null ? 401 : 200, claims == null ? Map.of("error", "invalid_token") : claims);
                return;
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
                if ("client_credentials".equals(grant)) {
                    json(exchange, 200, Map.of("access_token", "cc-token", "token_type", "Bearer", "expires_in", 120, "scope", params.getOrDefault("scope", "")));
                    return;
                }
                if ("refresh_token".equals(grant)) {
                    Map<String, String> row = stub.refresh.get(params.getOrDefault("refresh_token", ""));
                    if (row == null) {
                        json(exchange, 400, Map.of("error", "invalid_grant"));
                        return;
                    }
                    Map<String, Object> minted = tokenFor(row);
                    Map<String, Object> claims = new LinkedHashMap<>(stub.access.get(minted.get("access_token")));
                    claims.remove("nonce");
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
                json(exchange, 200, tokenFor(row));
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
        doc.put("id_token_signing_alg_values_supported", List.of("RS256"));
        doc.put("token_endpoint_auth_methods_supported", List.of("client_secret_basic", "client_secret_post", "private_key_jwt"));
        doc.put("code_challenge_methods_supported", List.of("S256"));
        doc.put("authorization_response_iss_parameter_supported", true);
        doc.put("scopes_supported", List.of(SCOPES.split(" ")));
        if (stub.par) doc.put("pushed_authorization_request_endpoint", stub.url + "/par");
        return doc;
    }

    static Map<String, Object> tokenFor(Map<String, String> row) throws Exception {
        String access = Long.toHexString(System.nanoTime());
        String refresh = Long.toHexString(System.nanoTime() + 1);
        long now = System.currentTimeMillis() / 1000;
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("iss", stub.url);
        payload.put("sub", row.get("sub"));
        payload.put("aud", stub.aud);
        payload.put("exp", stub.exp != null ? stub.exp : now + 300);
        payload.put("iat", stub.exp != null ? stub.exp : now);
        payload.put("nonce", row.get("nonce"));
        payload.put("email", row.get("email"));
        payload.put("name", "Demo User");
        payload.put("preferred_username", row.get("sub"));
        payload.put("sid", row.get("sid"));
        payload.put("at_hash", stub.badAtHash ? "aaaa" : IdToken.hashClaim(access, "RS256"));
        String token = idToken(payload, stub.corrupt);
        stub.refresh.put(refresh, row);
        stub.access.put(access, payload);
        stub.aud = CLIENT;
        stub.corrupt = false;
        stub.badAtHash = false;
        stub.exp = null;
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("access_token", access);
        out.put("token_type", "Bearer");
        out.put("expires_in", 300);
        out.put("refresh_token", refresh);
        out.put("id_token", token);
        out.put("scope", SCOPES);
        return out;
    }

    static String idToken(Map<String, Object> payload, boolean corrupt) throws Exception {
        String header = Codec.b64UrlEncode("{\"alg\":\"RS256\",\"kid\":\"op\",\"typ\":\"JWT\"}".getBytes(StandardCharsets.UTF_8));
        String body = Codec.b64UrlEncode(Jsons.write(payload).getBytes(StandardCharsets.UTF_8));
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(providerKeys.getPrivate());
        signature.update((header + "." + body).getBytes(StandardCharsets.US_ASCII));
        String sig = Codec.b64UrlEncode(signature.sign());
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
        byte[] raw = Jsons.write(body).getBytes(StandardCharsets.UTF_8);
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

    static final class Stub {
        volatile String url = "";
        volatile boolean par;
        volatile boolean corrupt;
        volatile String aud = CLIENT;
        volatile Long exp;
        volatile boolean badAtHash;
        final Map<String, Map<String, String>> codes = new ConcurrentHashMap<>();
        final Map<String, Map<String, String>> refresh = new ConcurrentHashMap<>();
        final Map<String, Map<String, Object>> access = new ConcurrentHashMap<>();
        final Map<String, Map<String, String>> pushed = new ConcurrentHashMap<>();
    }
}
