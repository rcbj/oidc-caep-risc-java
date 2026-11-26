// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.oidc;

import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.iyasec.pep.Access;
import com.iyasec.pep.Decision;
import com.iyasec.pep.Pep;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.time.Duration;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Local mode through {@link RelyingParty#decide}: nothing is held, then the pulled policy decides in process. */
class LocalModeDecideTest {
    /** Permits {@code read} and nothing else. */
    private static final String READ_ONLY = "<Policy xmlns=\"urn:oasis:names:tc:xacml:3.0:core:schema:wd-17\" PolicyId=\"orders\" Version=\"1.0\" RuleCombiningAlgId=\"urn:oasis:names:tc:xacml:3.0:rule-combining-algorithm:deny-unless-permit\"><Target/><Rule RuleId=\"read\" Effect=\"Permit\"><Target><AnyOf><AllOf><Match MatchId=\"urn:oasis:names:tc:xacml:1.0:function:string-equal\"><AttributeValue DataType=\"http://www.w3.org/2001/XMLSchema#string\">read</AttributeValue><AttributeDesignator Category=\"urn:oasis:names:tc:xacml:3.0:attribute-category:action\" AttributeId=\"urn:oasis:names:tc:xacml:1.0:action:action-id\" DataType=\"http://www.w3.org/2001/XMLSchema#string\" MustBePresent=\"false\"/></Match></AllOf></AnyOf></Target></Rule></Policy>";

    @Test
    void localModeFailsClosedThenDecidesInProcess() throws Exception {
        AtomicBoolean policiesUp = new AtomicBoolean(false);
        AtomicInteger evaluations = new AtomicInteger();
        AtomicBoolean policiesRequested = new AtomicBoolean(false);
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        ExecutorService pool = Executors.newCachedThreadPool(runnable -> {
            Thread thread = new Thread(runnable, "local-pdp");
            thread.setDaemon(true);
            return thread;
        });
        server.createContext("/", exchange -> handle(exchange, policiesUp, evaluations, policiesRequested));
        server.setExecutor(pool);
        RelyingParty rp = null;
        try {
            server.start();
            Path key = Files.createTempFile("oidc-pep-local-", ".pem");
            key.toFile().deleteOnExit();
            Files.writeString(key, pemOf(ec()));
            int port = server.getAddress().getPort();
            rp = RelyingParty.create(party(section(key.toAbsolutePath().toString(), port)));
            RelyingParty.Login login = login();
            Decision closed = rp.decide(login, Access.of("read", "order", "42"));
            assertEquals(Decision.Kind.UNAVAILABLE, closed.kind(), closed.why());

            policiesUp.set(true);
            Pep pep = rp.pep();
            boolean held = false;
            long deadline = System.nanoTime() + Duration.ofSeconds(8).toNanos();
            while (System.nanoTime() < deadline) {
                if (pep.status().holdsPolicy) {
                    held = true;
                    break;
                }
                Thread.sleep(100);
            }
            assertTrue(held, "the poll pulled once the service answered: " + pep.status().lastError);
            Decision read = rp.decide(login, Access.of("read", "order", "42"));
            assertTrue(read.isPermit(), read.why());
            Decision write = rp.decide(login, Access.of("write", "order", "42"));
            assertEquals(Decision.Kind.DENY, write.kind(), write.why());
            assertEquals(0, evaluations.get(), "decided in process");
            assertTrue(policiesRequested.get(), "the policies path was requested");
        } finally {
            if (rp != null && rp.pep() != null) {
                Pep pep = rp.pep();
                pep.stop();
                pep.close();
            }
            server.stop(0);
            pool.shutdownNow();
        }
    }

    private static void handle(HttpExchange exchange, AtomicBoolean policiesUp, AtomicInteger evaluations, AtomicBoolean policiesRequested) {
        try {
            exchange.getRequestBody().readAllBytes();
            String method = exchange.getRequestMethod();
            String path = exchange.getRequestURI().getPath();
            if ("POST".equals(method) && "/access/v1/evaluation".equals(path)) evaluations.incrementAndGet();
            if ("/xacml/pep/policies".equals(path)) policiesRequested.set(true);
            String authorization = exchange.getRequestHeaders().getFirst("Authorization");
            boolean dpop = authorization != null && authorization.startsWith("DPoP ");
            if (!"/oauth2/token".equals(path) && !dpop) {
                json(exchange, 401, error("invalid_token"));
                return;
            }
            if ("POST".equals(method) && "/oauth2/token".equals(path)) {
                ObjectNode body = Jsons.MAPPER.createObjectNode();
                body.put("access_token", "pep-token");
                body.put("token_type", "DPoP");
                body.put("expires_in", 300);
                json(exchange, 200, body);
                return;
            }
            if ("POST".equals(method) && "/xacml/pep/register".equals(path)) {
                json(exchange, 201, Jsons.MAPPER.createObjectNode().put("registered", true));
                return;
            }
            if ("POST".equals(method) && "/xacml/pep/heartbeat".equals(path)) {
                ObjectNode body = Jsons.MAPPER.createObjectNode();
                body.put("acknowledged", true);
                body.put("current", true);
                json(exchange, 200, body);
                return;
            }
            if ("GET".equals(method) && "/xacml/pep/authzen-catalogue".equals(path)) {
                json(exchange, 200, catalogue());
                return;
            }
            if ("GET".equals(method) && "/xacml/pep/policies".equals(path)) {
                boolean up = policiesUp.get();
                json(exchange, up ? 200 : 503, up ? policies() : error("server_error"));
                return;
            }
            if ("POST".equals(method) && "/admin-api/pep-audit".equals(path)) {
                json(exchange, 200, Jsons.MAPPER.createObjectNode().put("acknowledged", 0));
                return;
            }
            if ("POST".equals(method) && "/access/v1/evaluation".equals(path)) {
                json(exchange, 200, Jsons.MAPPER.createObjectNode().put("decision", true));
                return;
            }
            json(exchange, 404, error("not_found"));
        } catch (Exception err) {
            if (exchange.getResponseCode() < 0) {
                try {
                    json(exchange, 500, error("server_error"));
                } catch (IOException ignored) {
                    // The client sees a closed connection.
                }
            }
        } finally {
            exchange.close();
        }
    }

    private static ObjectNode catalogue() {
        ObjectNode body = Jsons.MAPPER.createObjectNode();
        body.put("syncToken", "c1");
        body.put("realm", "r1");
        ArrayNode rows = body.putArray("rows");
        rows.addObject().put("object", "subject").put("property", "acr").put("attributeId", "urn:example:acr");
        rows.addObject().put("object", "subject").put("property", "email").put("attributeId", "urn:example:email");
        body.putObject("settings").put("obligationsProfile", false);
        return body;
    }

    private static ObjectNode policies() {
        ObjectNode body = Jsons.MAPPER.createObjectNode();
        body.put("syncToken", "p1");
        ObjectNode policy = body.putArray("policies").addObject();
        policy.put("policyId", "orders");
        policy.put("kind", "Policy");
        policy.put("version", "1.0");
        policy.put("isRoot", true);
        policy.put("document", READ_ONLY);
        return body;
    }

    private static ObjectNode error(String code) {
        return Jsons.MAPPER.createObjectNode().put("error", code);
    }

    private static void json(HttpExchange exchange, int status, ObjectNode body) throws IOException {
        byte[] bytes = Jsons.MAPPER.writeValueAsBytes(body);
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, bytes.length);
        exchange.getResponseBody().write(bytes);
    }

    private static Map<String, Object> section(String keyPath, int port) {
        Map<String, Object> section = new LinkedHashMap<>();
        section.put("name", "pep-demo");
        section.put("mode", "local");
        section.put("assertionKey", keyPath);
        section.put("pdpUrl", "http://127.0.0.1:" + port);
        section.put("signals", false);
        section.put("pollIntervalMs", 1000);
        section.put("heartbeatIntervalMs", 60000);
        return section;
    }

    private static Map<String, Object> party(Map<String, Object> pep) {
        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("issuer", "https://idp.example");
        metadata.put("authorization_endpoint", "https://idp.example/oauth2/authorize");
        metadata.put("token_endpoint", "https://idp.example/oauth2/token");
        metadata.put("jwks_uri", "https://idp.example/jwks");
        metadata.put("id_token_signing_alg_values_supported", List.of("RS256"));
        metadata.put("token_endpoint_auth_methods_supported", List.of("client_secret_basic", "private_key_jwt"));
        Map<String, Object> doc = new LinkedHashMap<>();
        doc.put("issuer", "https://idp.example");
        doc.put("metadata", metadata);
        doc.put("clientId", "app");
        doc.put("clientSecret", "secret");
        doc.put("tokenEndpointAuthMethod", "client_secret_basic");
        doc.put("redirectUri", "https://app.example/callback");
        doc.put("dpop", "never");
        doc.put("signals", false);
        doc.put("pep", pep);
        return doc;
    }

    private static RelyingParty.Login login() {
        RelyingParty.Login login = new RelyingParty.Login();
        login.subject = "0b6e-uuid";
        login.preferredUsername = "alice";
        login.claims = new LinkedHashMap<>();
        login.claims.put("sub", "0b6e-uuid");
        login.claims.put("preferred_username", "alice");
        login.claims.put("acr", "urn:example:mfa");
        return login;
    }

    private static byte[] ec() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        return generator.generateKeyPair().getPrivate().getEncoded();
    }

    private static String pemOf(byte[] der) {
        return "-----BEGIN PRIVATE KEY-----\n" + Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.UTF_8)).encodeToString(der) + "\n-----END PRIVATE KEY-----\n";
    }
}
