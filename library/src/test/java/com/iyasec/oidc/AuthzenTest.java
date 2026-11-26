// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.oidc;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.iyasec.pep.Access;
import com.iyasec.pep.Decision;
import com.iyasec.pep.Obligation;
import com.iyasec.pep.Pep;
import com.iyasec.pep.authzen.Catalogue;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Comparator;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The AuthZEN case table ({@code authzen_cases.json}) decided in local mode
 * through {@link RelyingParty#decide}. What is compared is the host-visible
 * answer: Permit with each obligation's kind and properties, Deny, or
 * Unavailable. A {@code knownLocalDefect} that is still wrong is not a
 * failure; one that now matches fails so the mark can be removed.
 */
class AuthzenTest {
    @Test
    void theTableIsWellFormed() throws Exception {
        JsonNode table = table();
        JsonNode applications = table.get("applications");
        JsonNode cases = table.get("cases");
        assertTrue(applications != null && applications.isObject());
        assertTrue(cases != null && cases.isArray());
        assertTrue(cases.size() >= 40, cases.size() + " cases");
        Set<String> names = new HashSet<>();
        for (JsonNode caze : cases) {
            String name = caze.path("name").asText();
            assertTrue(names.add(name), "a case name is used twice: " + name);
            assertTrue(applications.has(caze.path("app").asText()), name);
            String decision = caze.path("expect").path("decision").asText();
            assertTrue("Permit".equals(decision) || "Deny".equals(decision) || "Unavailable".equals(decision), name);
        }
        applications.fieldNames().forEachRemaining(app -> {
            int roots = 0;
            for (JsonNode policy : table.get("policies")) {
                if (app.equals(policy.path("app").asText()) && policy.path("root").isBoolean() && policy.get("root").booleanValue()) {
                    roots++;
                }
            }
            assertEquals(1, roots, app + " has one root");
        });
        ObjectNode pull = Jsons.MAPPER.createObjectNode();
        pull.set("rows", table.get("catalogue").deepCopy());
        Catalogue catalogue = Catalogue.fromPull(pull);
        assertEquals(table.get("catalogue").size(), catalogue.rows.size());
    }

    @Test
    void theTableDecidesAsExpectedInLocalMode() throws Exception {
        JsonNode table = table();
        List<String> missing = new ArrayList<>();
        for (JsonNode policy : table.get("policies")) {
            if (xacmlOf(policy).isEmpty()) missing.add(policy.path("name").asText());
        }
        assertTrue(missing.isEmpty(), "policies without xacml " + missing);
        AtomicInteger pipQueries = new AtomicInteger();
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        ExecutorService pool = Executors.newCachedThreadPool(runnable -> {
            Thread thread = new Thread(runnable, "authzen-pdp");
            thread.setDaemon(true);
            return thread;
        });
        server.createContext("/", exchange -> handle(exchange, table, pipQueries));
        server.setExecutor(pool);
        Map<String, RelyingParty> parties = new LinkedHashMap<>();
        try {
            server.start();
            String origin = "http://127.0.0.1:" + server.getAddress().getPort();
            JsonNode applications = table.get("applications");
            List<Map.Entry<String, JsonNode>> apps = new ArrayList<>();
            applications.fields().forEachRemaining(apps::add);
            for (Map.Entry<String, JsonNode> entry : apps) {
                String key = entry.getKey();
                String identifier = entry.getValue().path("identifier").asText();
                String name = "pep-az-" + key + "-local";
                Path pem = Files.createTempFile("oidc-authzen-" + key + "-", ".pem");
                pem.toFile().deleteOnExit();
                Files.writeString(pem, pemOf(ec()));
                Map<String, Object> section = pepSection(name, pem.toAbsolutePath().toString(), identifier, origin, table.get("supportedObligations"));
                RelyingParty rp = RelyingParty.create(party(section, identifier));
                parties.put(key, rp);
                assertTrue(waitReady(rp), name + " never held its policy: " + rp.pep().status().lastError);
            }
            List<String> wrong = new ArrayList<>();
            JsonNode cases = table.get("cases");
            for (int i = 0; i < cases.size(); i++) {
                JsonNode caze = cases.get(i);
                String name = caze.path("name").asText();
                RelyingParty rp = parties.get(caze.path("app").asText());
                if (rp == null) {
                    wrong.add(name + ": no relying party");
                    continue;
                }
                Decision decision = decide(rp, caze, i);
                JsonNode got = answerOf(decision);
                JsonNode expected = expectedOf(caze);
                boolean right = got.equals(expected);
                if (caze.path("knownLocalDefect").isTextual()) {
                    if (right) {
                        wrong.add(name + ": local now answers as expected; remove knownLocalDefect");
                    } else {
                        System.err.println("known local defect, still present: " + name + ": got " + got + ", expected " + expected);
                    }
                } else if (!right) {
                    wrong.add(name + ": got " + got + " (" + whyOf(decision) + "), expected " + expected);
                }
            }
            assertTrue(pipQueries.get() > 0, "the PIP was asked");
            assertTrue(wrong.isEmpty(), wrong.size() + " of " + cases.size() + " cases:\n" + String.join("\n", wrong));
        } finally {
            for (RelyingParty rp : parties.values()) {
                if (rp.pep() != null) {
                    Pep pep = rp.pep();
                    pep.stop();
                    pep.close();
                }
            }
            server.stop(0);
            pool.shutdownNow();
        }
    }

    /**
     * One case. The session store keeps tokens, not the sign-in, so a live
     * session is decided as that sign-in. An ended session is dropped with
     * {@link RelyingParty#removeSession} and denied without asking.
     */
    private static Decision decide(RelyingParty rp, JsonNode caze, int index) {
        RelyingParty.Login login = loginOf(caze);
        Access access = accessOf(caze);
        JsonNode session = caze.get("session");
        if (session == null || !session.isTextual()) return rp.decide(login, access);
        String id = "authzen-case-" + index;
        rp.sessionStore().put(id, new SessionTokens(login.subject, "access-token", "Bearer", null, "id-token", System.currentTimeMillis() + 3_600_000L, "openid"));
        if ("ended".equals(session.asText())) rp.removeSession(id);
        if (rp.sessionStore().get(id) == null) return Decision.deny("no signed-in session");
        return rp.decide(login, access);
    }

    private static RelyingParty.Login loginOf(JsonNode caze) {
        JsonNode loginNode = caze.path("login");
        String username = loginNode.path("username").isTextual() ? loginNode.get("username").asText() : "";
        Map<String, Object> claims = new LinkedHashMap<>();
        JsonNode raw = loginNode.get("claims");
        if (raw != null && raw.isObject()) {
            raw.fields().forEachRemaining(entry -> claims.put(entry.getKey(), Jsons.MAPPER.convertValue(entry.getValue(), Object.class)));
        }
        String subject = "sub-" + username;
        claims.put("sub", subject);
        claims.put("preferred_username", username);
        RelyingParty.Login login = new RelyingParty.Login();
        login.subject = subject;
        login.preferredUsername = username;
        login.claims = claims;
        return login;
    }

    private static Access accessOf(JsonNode caze) {
        JsonNode accessNode = caze.path("access");
        String action = accessNode.path("action").isTextual() ? accessNode.get("action").asText() : "";
        String type = accessNode.path("type").isTextual() ? accessNode.get("type").asText() : "";
        String id = accessNode.path("id").isTextual() ? accessNode.get("id").asText() : "";
        Access access = Access.of(action, type, id);
        access.actionProperties = nodeMap(accessNode.get("actionProperties"));
        access.resourceProperties = nodeMap(accessNode.get("resource"));
        access.context = nodeMap(accessNode.get("context"));
        return access;
    }

    private static Map<String, JsonNode> nodeMap(JsonNode node) {
        Map<String, JsonNode> out = new LinkedHashMap<>();
        if (node != null && node.isObject()) node.fields().forEachRemaining(entry -> out.put(entry.getKey(), entry.getValue().deepCopy()));
        return out;
    }

    private static JsonNode answerOf(Decision decision) {
        ObjectNode answer = Jsons.MAPPER.createObjectNode();
        if (decision.kind() == Decision.Kind.PERMIT) {
            answer.put("decision", "Permit");
            List<ObjectNode> handed = new ArrayList<>();
            for (Obligation obligation : decision.obligations()) {
                ObjectNode item = Jsons.MAPPER.createObjectNode();
                item.put("type", obligation.kind);
                item.set("properties", obligation.properties.deepCopy());
                handed.add(item);
            }
            handed.sort(Comparator.comparing(JsonNode::toString));
            if (!handed.isEmpty()) {
                ArrayNode array = answer.putArray("obligations");
                handed.forEach(array::add);
            }
        } else if (decision.kind() == Decision.Kind.DENY) {
            answer.put("decision", "Deny");
        } else {
            answer.put("decision", "Unavailable");
        }
        return answer;
    }

    private static String whyOf(Decision decision) {
        return decision.kind() == Decision.Kind.PERMIT ? "" : decision.why();
    }

    private static JsonNode expectedOf(JsonNode caze) {
        JsonNode expect = caze.get("expect");
        List<JsonNode> handed = new ArrayList<>();
        JsonNode obligations = expect == null ? null : expect.get("obligations");
        if (obligations != null && obligations.isArray()) obligations.forEach(handed::add);
        handed.sort(Comparator.comparing(JsonNode::toString));
        ObjectNode answer = Jsons.MAPPER.createObjectNode();
        JsonNode decision = expect == null ? null : expect.get("decision");
        if (decision == null || decision.isNull()) answer.putNull("decision");
        else answer.set("decision", decision.deepCopy());
        if (!handed.isEmpty()) {
            ArrayNode array = answer.putArray("obligations");
            for (JsonNode item : handed) array.add(item.deepCopy());
        }
        return answer;
    }

    private static boolean waitReady(RelyingParty rp) throws InterruptedException {
        Pep pep = rp.pep();
        long deadline = System.nanoTime() + Duration.ofSeconds(60).toNanos();
        while (System.nanoTime() < deadline) {
            if (pep.status().registered && pep.status().holdsPolicy) return true;
            Thread.sleep(200);
        }
        return false;
    }

    private static void handle(HttpExchange exchange, JsonNode table, AtomicInteger pipQueries) {
        try {
            byte[] raw = exchange.getRequestBody().readAllBytes();
            String method = exchange.getRequestMethod();
            String path = exchange.getRequestURI().getPath();
            String body = new String(raw, StandardCharsets.UTF_8);
            if ("POST".equals(method) && "/oauth2/token".equals(path)) {
                ObjectNode token = Jsons.MAPPER.createObjectNode();
                token.put("access_token", "pep-token");
                token.put("token_type", "DPoP");
                token.put("expires_in", 300);
                json(exchange, 200, token);
                return;
            }
            if ("POST".equals(method) && "/xacml/pep/register".equals(path)) {
                json(exchange, 201, Jsons.MAPPER.createObjectNode().put("registered", true));
                return;
            }
            if ("POST".equals(method) && "/xacml/pep/heartbeat".equals(path)) {
                ObjectNode beat = Jsons.MAPPER.createObjectNode();
                beat.put("acknowledged", true);
                beat.put("current", true);
                json(exchange, 200, beat);
                return;
            }
            if ("POST".equals(method) && "/admin-api/pep-audit".equals(path)) {
                json(exchange, 200, Jsons.MAPPER.createObjectNode().put("acknowledged", 0));
                return;
            }
            if ("GET".equals(method) && "/xacml/pep/authzen-catalogue".equals(path)) {
                json(exchange, 200, catalogue(table));
                return;
            }
            if ("GET".equals(method) && "/xacml/pep/policies".equals(path)) {
                String name = queryParam(exchange, "pep");
                String app = name.startsWith("pep-az-") ? name.substring("pep-az-".length()) : name;
                if (app.endsWith("-local")) app = app.substring(0, app.length() - "-local".length());
                json(exchange, 200, policies(table, app));
                return;
            }
            if ("POST".equals(method) && "/xacml/pip".equals(path)) {
                pipQueries.incrementAndGet();
                xml(exchange, pipAnswer(table, body));
                return;
            }
            json(exchange, 404, Jsons.MAPPER.createObjectNode().put("error", "not_found"));
        } catch (Exception err) {
            if (exchange.getResponseCode() < 0) {
                try {
                    json(exchange, 500, Jsons.MAPPER.createObjectNode().put("error", "server_error"));
                } catch (IOException ignored) {
                    // The client sees a closed connection.
                }
            }
        } finally {
            exchange.close();
        }
    }

    private static ObjectNode catalogue(JsonNode table) {
        ObjectNode body = Jsons.MAPPER.createObjectNode();
        body.put("syncToken", "c1");
        JsonNode rows = table.get("catalogue");
        body.set("rows", rows == null ? Jsons.MAPPER.createArrayNode() : rows.deepCopy());
        ArrayNode fga = body.putArray("fgaApplications");
        JsonNode applications = table.get("applications");
        if (applications != null && applications.isObject()) {
            applications.fields().forEachRemaining(entry -> {
                JsonNode app = entry.getValue();
                JsonNode flag = app.get("fga");
                JsonNode identifier = app.get("identifier");
                if (flag != null && flag.isBoolean() && flag.booleanValue() && identifier != null && identifier.isTextual()) {
                    fga.add(identifier.asText());
                }
            });
        }
        body.putObject("settings").put("obligationsProfile", true);
        return body;
    }

    private static ObjectNode policies(JsonNode table, String app) {
        ObjectNode body = Jsons.MAPPER.createObjectNode();
        body.put("syncToken", "p-" + app);
        ArrayNode rows = body.putArray("policies");
        for (JsonNode policy : table.get("policies")) {
            if (app.equals(policy.path("app").asText())) rows.add(policyRow(policy));
        }
        body.putArray("withheld");
        body.put("note", "");
        return body;
    }

    private static ObjectNode policyRow(JsonNode policy) {
        String document = xacmlOf(policy);
        int at = document.indexOf("<Policy");
        String root = at < 0 ? document : document.substring(at);
        boolean set = root.startsWith("<PolicySet");
        int end = root.indexOf('>');
        String head = end < 0 ? root : root.substring(0, end);
        String policyId = attributeIn(head, set ? "PolicySetId" : "PolicyId");
        String version = attributeIn(head, "Version");
        ObjectNode row = Jsons.MAPPER.createObjectNode();
        JsonNode name = policy.get("name");
        row.put("name", name != null && name.isTextual() ? name.asText() : "");
        row.put("policyId", policyId == null ? "" : policyId);
        row.put("kind", set ? "PolicySet" : "Policy");
        row.put("version", version == null ? "1.0" : version);
        JsonNode rootFlag = policy.get("root");
        row.put("isRoot", rootFlag != null && rootFlag.isBoolean() && rootFlag.booleanValue());
        row.put("description", "");
        row.put("document", document);
        return row;
    }

    private static String pipAnswer(JsonNode table, String query) {
        String subject = pipSubject(query);
        JsonNode user = null;
        JsonNode users = table.get("users");
        if (users != null && users.isArray()) {
            for (JsonNode candidate : users) {
                if (subject.equals(candidate.path("username").asText())) {
                    user = candidate;
                    break;
                }
            }
        }
        Map<String, StringBuilder> byCategory = new TreeMap<>();
        String[] pieces = query.split("<AttributeDesignator", -1);
        for (int i = 1; i < pieces.length; i++) {
            String piece = pieces[i];
            int slash = piece.indexOf("/>");
            String tag = slash < 0 ? piece : piece.substring(0, slash);
            String category = attributeIn(tag, "Category");
            String id = attributeIn(tag, "AttributeId");
            String dataType = attributeIn(tag, "DataType");
            if (category == null || id == null || dataType == null) continue;
            String value = null;
            if (user != null) {
                JsonNode attribute = user.path("attributes").get(id);
                if (attribute != null && attribute.isTextual()) value = attribute.asText();
            }
            if (value == null) continue;
            byCategory.computeIfAbsent(category, key -> new StringBuilder()).append("<Attribute AttributeId=\"").append(id)
                    .append("\" IncludeInResult=\"false\"><AttributeValue DataType=\"").append(dataType).append("\">")
                    .append(value).append("</AttributeValue></Attribute>");
        }
        String xacml = "urn:oasis:names:tc:xacml:3.0:core:schema:wd-17";
        StringBuilder out = new StringBuilder("<PIPResponse xmlns=\"urn:sts:xacml:pip:1.0\">");
        for (Map.Entry<String, StringBuilder> entry : byCategory.entrySet()) {
            out.append("<Attributes xmlns=\"").append(xacml).append("\" Category=\"").append(entry.getKey()).append("\">")
                    .append(entry.getValue()).append("</Attributes>");
        }
        out.append("</PIPResponse>");
        return out.toString();
    }

    private static String pipSubject(String query) {
        int at = query.indexOf("subject:subject-id");
        if (at < 0) return "";
        int value = query.indexOf("<AttributeValue", at);
        if (value < 0) return "";
        int start = query.indexOf('>', value);
        if (start < 0) return "";
        int end = query.indexOf("</AttributeValue>", start + 1);
        if (end < 0) return "";
        return query.substring(start + 1, end);
    }

    private static String attributeIn(String tag, String name) {
        String key = name + "=\"";
        int start = tag.indexOf(key);
        if (start < 0) return null;
        start += key.length();
        int end = tag.indexOf('"', start);
        if (end < 0) return null;
        return tag.substring(start, end).replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", "\"").replace("&amp;", "&");
    }

    private static String xacmlOf(JsonNode policy) {
        JsonNode lines = policy.get("xacml");
        if (lines == null || !lines.isArray()) return "";
        StringBuilder out = new StringBuilder();
        for (JsonNode line : lines) {
            if (!line.isTextual()) continue;
            if (out.length() > 0) out.append('\n');
            out.append(line.asText());
        }
        return out.toString();
    }

    private static String queryParam(HttpExchange exchange, String name) {
        String raw = exchange.getRequestURI().getRawQuery();
        if (raw == null || raw.isEmpty()) return "";
        for (String part : raw.split("&")) {
            int eq = part.indexOf('=');
            String key = URLDecoder.decode(eq < 0 ? part : part.substring(0, eq), StandardCharsets.UTF_8);
            if (!name.equals(key)) continue;
            return eq < 0 ? "" : URLDecoder.decode(part.substring(eq + 1), StandardCharsets.UTF_8);
        }
        return "";
    }

    private static void json(HttpExchange exchange, int status, ObjectNode body) throws IOException {
        byte[] bytes = Jsons.MAPPER.writeValueAsBytes(body);
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, bytes.length);
        exchange.getResponseBody().write(bytes);
    }

    private static void xml(HttpExchange exchange, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/xml");
        exchange.sendResponseHeaders(200, bytes.length);
        exchange.getResponseBody().write(bytes);
    }

    private static Map<String, Object> pepSection(String name, String keyPath, String application, String pdpUrl, JsonNode supported) {
        Map<String, Object> section = new LinkedHashMap<>();
        section.put("name", name);
        section.put("mode", "local");
        section.put("assertionKey", keyPath);
        section.put("application", application);
        section.put("pdpUrl", pdpUrl);
        section.put("signals", false);
        section.put("pollIntervalMs", 1000);
        section.put("heartbeatIntervalMs", 10000);
        List<String> obligations = new ArrayList<>();
        if (supported != null && supported.isArray()) {
            for (JsonNode item : supported) if (item.isTextual()) obligations.add(item.asText());
        }
        section.put("supportedObligations", obligations);
        return section;
    }

    private static Map<String, Object> party(Map<String, Object> pep, String clientId) {
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
        doc.put("clientId", clientId);
        doc.put("clientSecret", "secret");
        doc.put("tokenEndpointAuthMethod", "client_secret_basic");
        doc.put("redirectUri", "https://app.example/callback");
        doc.put("dpop", "never");
        doc.put("signals", false);
        doc.put("pep", pep);
        return doc;
    }

    private static JsonNode table() throws IOException {
        try (InputStream in = AuthzenTest.class.getResourceAsStream("/authzen_cases.json")) {
            if (in == null) throw new IOException("authzen_cases.json is not on the test classpath");
            return Jsons.MAPPER.readTree(in);
        }
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
