// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.oidc;

import com.iyasec.oidc.ssf.Events;
import com.iyasec.oidc.ssf.SecEvent;
import com.iyasec.oidc.ssf.SignalsReceiver;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.Executors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The Shared Signals receiver against a stub transmitter. */
class SignalsReceiverTest {
    static KeyPair signing;
    static KeyPair other;
    static Map<String, Object> jwk;
    static HttpServer server;
    static Transmitter stub;

    @BeforeAll
    static void up() throws Exception {
        signing = rsa();
        other = rsa();
        jwk = jwk((RSAPublicKey) signing.getPublic(), "k1");
        stub = new Transmitter();
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", SignalsReceiverTest::handle);
        server.setExecutor(Executors.newCachedThreadPool());
        server.start();
        stub.base = "http://127.0.0.1:" + server.getAddress().getPort();
    }

    @AfterAll
    static void down() {
        if (server != null) server.stop(0);
    }

    @Test
    void verifiesASetAgainstTheJwks() throws Exception {
        Map<String, Object> verified = SecEvent.verifyCompactJws(jws(Map.of("a", 1), signing, null), List.of(jwk));
        assertEquals(1, ((Number) Jsons.map(verified.get("payload")).get("a")).intValue());
        OidcError mismatch = assertThrows(OidcError.class, () -> SecEvent.verifyCompactJws(jws(Map.of("a", 1), other, null), List.of(jwk)));
        assertTrue(mismatch.getMessage().contains("does not verify"));
        Map<String, Object> header = new LinkedHashMap<>();
        header.put("alg", "RS256");
        header.put("kid", "nope");
        OidcError kid = assertThrows(OidcError.class, () -> SecEvent.verifyCompactJws(jws(Map.of("a", 1), signing, header), List.of(jwk)));
        assertTrue(kid.getMessage().contains("kid nope"));
        OidcError none = assertThrows(OidcError.class, () -> SecEvent.verifyCompactJws(jws(Map.of("a", 1), signing, Map.of("alg", "none")), List.of(jwk)));
        assertTrue(none.getMessage().contains("does not verify"));
    }

    @Test
    void readsSubjectForms() {
        assertEquals("https://schemas.openid.net/secevent/caep/event-type/session-revoked", Events.EVENT.get("sessionRevoked"));
        assertEquals("https://schemas.openid.net/secevent/risc/event-type/credential-compromise", Events.EVENT.get("credentialCompromise"));
        Map<String, Object> complex = new LinkedHashMap<>();
        complex.put("format", "complex");
        complex.put("user", Map.of("format", "iss_sub", "iss", "https://i", "sub", "urn:uuid:a"));
        complex.put("session", Map.of("format", "opaque", "id", "S1"));
        assertEquals(Map.of("person", "urn:uuid:a", "idpSession", "S1"), Events.subjectOf(complex, "https://i"));
        assertEquals(Map.of(), Events.subjectOf(Map.of("format", "iss_sub", "iss", "https://other", "sub", "urn:uuid:a"), "https://i"));
        assertEquals(Map.of("email", "A@x.com"), Events.subjectOf(Map.of("format", "email", "email", "A@x.com"), "https://i"));
    }

    @Test
    void pollsAndEndsOnlyTheNamedSession() throws Exception {
        List<List<String>> ended = new ArrayList<>();
        List<Map<String, Object>> seen = new ArrayList<>();
        SignalsReceiver receiver = SignalsReceiver.builder(stub.base, (ids, event) -> ended.add(new ArrayList<>(ids)))
                .headers(() -> Map.of("authorization", "Bearer app-token"))
                .pollIntervalMs(60_000)
                .log(new SignalsReceiver.Log() {
                    public void info(String message) {}
                    public void warn(String message) {}
                    public void error(String message) {}
                })
                .build();
        receiver.on("*", seen::add);
        receiver.start();
        receiver.stop();
        assertEquals(1, stub.created);
        assertEquals("Bearer app-token", stub.authorization);
        assertEquals("s1", receiver.stream().get("stream_id"));
        receiver.track(session("L-a1", "alice", "IDP-A1"));
        receiver.track(session("L-a2", "alice", "IDP-A2"));
        receiver.track(session("L-b1", "bob", "IDP-B1"));
        String revoked = deliver(Events.EVENT.get("sessionRevoked"), complex("alice", "IDP-A1"), null, signing, null, null);
        Map<String, Object> extra = new LinkedHashMap<>();
        extra.put("credential_type", "password");
        deliver(Events.EVENT.get("credentialChange"), Map.of("format", "iss_sub", "iss", stub.base, "sub", "urn:uuid:bob"), extra, signing, null, null);
        receiver.pollOnce();
        assertEquals(List.of(List.of("L-a1")), ended);
        assertEquals(2, seen.size());
        assertEquals(Boolean.TRUE, seen.get(0).get("ended"));
        assertEquals(Events.EVENT.get("credentialChange"), seen.get(1).get("type"));
        assertEquals(Boolean.FALSE, seen.get(1).get("ended"));
        receiver.pollOnce();
        List<String> acked = new ArrayList<>(stub.acked);
        List<String> expected = new ArrayList<>();
        expected.add(revoked);
        for (String item : acked) if (!item.equals(revoked)) expected.add(item);
        assertEquals(expected, acked);
        String bad = deliver(Events.EVENT.get("accountDisabled"), Map.of("format", "email", "email", "alice@example.com"), null, other, null, null);
        receiver.pollOnce();
        receiver.pollOnce();
        @SuppressWarnings("unchecked")
        Map<String, Object> problem = (Map<String, Object>) stub.errs.get(bad);
        assertEquals("invalid_key", problem.get("err"));
        receiver.verify("abc");
        receiver.stop();
    }

    @Test
    void sendsEveryTransmitterCallThroughTheTransport() throws Exception {
        List<String> sent = new CopyOnWriteArrayList<>();
        SignalsReceiver receiver = SignalsReceiver.builder(stub.base, (ids, event) -> {})
                .transport((method, url, headers, body) -> {
                    sent.add(method + " " + url.substring(stub.base.length()));
                    Map<String, String> withToken = new LinkedHashMap<>(headers);
                    withToken.put("authorization", "Bearer app-token");
                    return Http.send(url, method, withToken, body, Map.of(), "ssf");
                })
                .pollIntervalMs(60_000)
                .log(new SignalsReceiver.Log() {
                    public void info(String message) {}
                    public void warn(String message) {}
                    public void error(String message) {}
                })
                .build();
        receiver.start();
        receiver.stop();
        receiver.pollOnce();
        receiver.verify("t");
        assertTrue(sent.contains("GET /.well-known/ssf-configuration"), String.valueOf(sent));
        assertTrue(sent.contains("GET /jwks"), String.valueOf(sent));
        assertTrue(sent.contains("GET /ssf/stream"), String.valueOf(sent));
        assertTrue(sent.stream().anyMatch(line -> line.startsWith("POST /ssf/poll/")), String.valueOf(sent));
        assertTrue(sent.contains("POST /ssf/verify"), String.valueOf(sent));
    }

    static Map<String, Object> session(String localId, String person, String sid) {
        Map<String, Object> session = new LinkedHashMap<>();
        session.put("localId", localId);
        session.put("person", "urn:uuid:" + person);
        session.put("email", person + "@example.com");
        session.put("idpSession", sid);
        return session;
    }

    static Map<String, Object> complex(String person, String sid) {
        Map<String, Object> subject = new LinkedHashMap<>();
        subject.put("format", "complex");
        subject.put("user", Map.of("format", "iss_sub", "iss", stub.base, "sub", "urn:uuid:" + person));
        subject.put("session", Map.of("format", "opaque", "id", sid));
        return subject;
    }

    static String deliver(String eventType, Map<String, Object> subId, Map<String, Object> extra, KeyPair key, String aud, String iss) throws Exception {
        String jti = UUID.randomUUID().toString();
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("iss", iss == null ? stub.base : iss);
        payload.put("aud", aud == null ? "my-app" : aud);
        payload.put("jti", jti);
        payload.put("iat", System.currentTimeMillis() / 1000);
        payload.put("sub_id", subId);
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("event_timestamp", 1);
        if (extra != null) body.putAll(extra);
        payload.put("events", Map.of(eventType, body));
        synchronized (stub.queue) {
            stub.queue.put(jti, jws(payload, key, null));
        }
        return jti;
    }

    static void handle(HttpExchange exchange) {
        try {
            byte[] raw = exchange.getRequestBody().readAllBytes();
            String text = new String(raw, StandardCharsets.UTF_8);
            stub.authorization = header(exchange, "authorization");
            String path = exchange.getRequestURI().getPath();
            if (!"Bearer app-token".equals(stub.authorization) && !"/.well-known/ssf-configuration".equals(path) && !path.startsWith("/jwks")) {
                json(exchange, 401, Map.of("error", "invalid_token"));
                return;
            }
            String base = stub.base;
            if ("/.well-known/ssf-configuration".equals(path)) {
                json(exchange, 200, Map.of(
                        "issuer", base,
                        "jwks_uri", base + "/jwks",
                        "configuration_endpoint", base + "/ssf/stream",
                        "verification_endpoint", base + "/ssf/verify",
                        "delivery_methods_supported", List.of("urn:ietf:rfc:8936")));
                return;
            }
            if ("/jwks".equals(path)) {
                json(exchange, 200, Map.of("keys", List.of(jwk)));
                return;
            }
            if ("/ssf/stream".equals(path) && "GET".equals(exchange.getRequestMethod())) {
                json(exchange, 200, stub.streams);
                return;
            }
            if ("/ssf/stream".equals(path) && "POST".equals(exchange.getRequestMethod())) {
                Map<String, Object> body = Jsons.map(Jsons.read(text));
                stub.created += 1;
                Map<String, Object> delivery = new LinkedHashMap<>();
                @SuppressWarnings("unchecked")
                Map<String, Object> asked = (Map<String, Object>) body.get("delivery");
                delivery.put("method", asked.get("method"));
                delivery.put("endpoint_url", base + "/ssf/poll/s" + stub.created);
                Map<String, Object> stream = new LinkedHashMap<>();
                stream.put("stream_id", "s" + stub.created);
                stream.put("iss", base);
                stream.put("aud", "my-app");
                stream.put("delivery", delivery);
                stream.put("events_requested", body.get("events_requested"));
                stream.put("events_delivered", body.get("events_requested"));
                stub.streams.add(stream);
                json(exchange, 201, stream);
                return;
            }
            if ("/ssf/verify".equals(path)) {
                exchange.getResponseHeaders().set("content-type", "application/json");
                exchange.sendResponseHeaders(204, -1);
                exchange.close();
                return;
            }
            if (path.startsWith("/ssf/poll/")) {
                Map<String, Object> body = text.isEmpty() ? Map.of() : Jsons.map(Jsons.read(text));
                if (body.get("ack") instanceof List<?> ack) {
                    for (Object jti : ack) {
                        stub.acked.add(String.valueOf(jti));
                        synchronized (stub.queue) { stub.queue.remove(String.valueOf(jti)); }
                    }
                }
                if (body.get("setErrs") instanceof Map<?, ?> errs) {
                    errs.forEach((key, value) -> stub.errs.put(String.valueOf(key), value));
                    for (Object key : errs.keySet()) synchronized (stub.queue) { stub.queue.remove(String.valueOf(key)); }
                }
                Map<String, Object> sets;
                synchronized (stub.queue) { sets = new LinkedHashMap<>(stub.queue); }
                json(exchange, 200, Map.of("sets", sets, "moreAvailable", false));
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

    static String jws(Map<String, Object> payload, KeyPair key, Map<String, Object> header) throws Exception {
        Map<String, Object> actual = header == null ? new LinkedHashMap<>(Map.of("alg", "RS256", "kid", "k1", "typ", "secevent+jwt")) : new LinkedHashMap<>(header);
        if ("none".equals(actual.get("alg"))) {
            String h = Codec.b64UrlEncode(Jsons.write(actual).getBytes(StandardCharsets.UTF_8));
            String p = Codec.b64UrlEncode(Jsons.write(payload).getBytes(StandardCharsets.UTF_8));
            return h + "." + p + "." + Codec.b64UrlEncode(new byte[] {1});
        }
        String h = Codec.b64UrlEncode(Jsons.write(actual).getBytes(StandardCharsets.UTF_8));
        String p = Codec.b64UrlEncode(Jsons.write(payload).getBytes(StandardCharsets.UTF_8));
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(key.getPrivate());
        signature.update((h + "." + p).getBytes(StandardCharsets.US_ASCII));
        return h + "." + p + "." + Codec.b64UrlEncode(signature.sign());
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

    static KeyPair rsa() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    static Map<String, Object> jwk(RSAPublicKey key, String kid) {
        byte[] modulus = key.getModulus().toByteArray();
        if (modulus[0] == 0) modulus = java.util.Arrays.copyOfRange(modulus, 1, modulus.length);
        byte[] exponent = key.getPublicExponent().toByteArray();
        if (exponent[0] == 0) exponent = java.util.Arrays.copyOfRange(exponent, 1, exponent.length);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("kty", "RSA");
        out.put("n", Codec.b64UrlEncode(modulus));
        out.put("e", Codec.b64UrlEncode(exponent));
        out.put("kid", kid);
        out.put("alg", "RS256");
        out.put("use", "sig");
        return out;
    }

    static final class Transmitter {
        volatile String base = "";
        volatile String authorization = "";
        volatile int created;
        final Map<String, String> queue = new LinkedHashMap<>();
        final List<String> acked = new CopyOnWriteArrayList<>();
        final Map<String, Object> errs = new LinkedHashMap<>();
        final List<Map<String, Object>> streams = new ArrayList<>();
    }
}
