// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.oidc.demo;

import com.iyasec.oidc.Config;
import com.iyasec.oidc.Jsons;
import com.iyasec.oidc.OidcError;
import com.iyasec.oidc.RelyingParty;
import com.iyasec.oidc.ssf.MemorySessionIndex;
import com.iyasec.oidc.ssf.SignalsReceiver;
import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;

/** Demo. GET /healthz, GET /, GET /login, GET /callback, POST /logout. */
public final class Demo {
    private static final Path ROOT = Path.of("").toAbsolutePath();
    private static final byte[] SECRET = secret();
    private static final Map<String, Session> SESSIONS = new ConcurrentHashMap<>();
    private static final SecureRandom RANDOM = new SecureRandom();
    private static volatile RelyingParty rp;
    private static volatile String receiverState = "";
    private static volatile SignalsReceiver receiver;
    private static volatile boolean secureCookies = true;
    private static volatile String configPath = ROOT.resolve("demo/oidc.json").toString();
    private static volatile String publicUrl;

    private Demo() {}

    public static void main(String[] args) throws Exception {
        for (int i = 0; i < args.length; i++) {
            if ("--config".equals(args[i]) && i + 1 < args.length) configPath = args[++i];
            else if ("--public-url".equals(args[i]) && i + 1 < args.length) publicUrl = args[++i].replaceAll("/+$", "");
        }
        if (System.getenv("OIDC_CONFIG") != null && !System.getenv("OIDC_CONFIG").isEmpty()) configPath = System.getenv("OIDC_CONFIG");
        int port = port();
        try {
            Map<String, Object> raw = loadRaw();
            applyRedirects(raw, port);
            URI redirect = URI.create(String.valueOf(raw.getOrDefault("redirectUri", raw.getOrDefault("redirect_uri", "http://localhost/"))));
            secureCookies = "https".equals(redirect.getScheme()) || "localhost".equals(redirect.getHost()) || "127.0.0.1".equals(redirect.getHost());
        } catch (Exception err) {
            System.err.println("cannot read configuration: " + err);
        }
        HttpServer server = HttpServer.create(new InetSocketAddress("0.0.0.0", port), 0);
        server.createContext("/", Demo::route);
        server.setExecutor(Executors.newCachedThreadPool());
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            if (receiver != null) receiver.stop();
            server.stop(0);
        }));
        server.start();
        System.out.println("oidc-caep-risc demo on port " + port);
    }

    private static void route(HttpExchange exchange) throws IOException {
        try {
            exchange.getRequestBody().readAllBytes();
            String path = exchange.getRequestURI().getPath();
            String method = exchange.getRequestMethod();
            if ("/healthz".equals(path)) {
                send(exchange, 200, "ok".getBytes(StandardCharsets.UTF_8), "text/plain", null);
                return;
            }
            if ("/styles.css".equals(path)) {
                send(exchange, 200, Files.readAllBytes(ROOT.resolve("demo/public/styles.css")), "text/css; charset=utf-8", null);
                return;
            }
            if ("/app.js".equals(path)) {
                send(exchange, 200, Files.readAllBytes(ROOT.resolve("demo/public/app.js")), "text/javascript; charset=utf-8", null);
                return;
            }
            if ("/".equals(path) && "GET".equals(method)) {
                home(exchange);
                return;
            }
            if ("/login".equals(path) && "GET".equals(method)) {
                login(exchange);
                return;
            }
            if ("/callback".equals(path) && "GET".equals(method)) {
                callback(exchange);
                return;
            }
            if ("/logout".equals(path) && "POST".equals(method)) {
                logout(exchange);
                return;
            }
            send(exchange, 404, page("Not found", "<h1>Not found</h1>"), "text/html; charset=utf-8", null);
        } catch (Exception err) {
            err.printStackTrace();
            try {
                send(exchange, 500, page("Error", "<h1>Something went wrong</h1><p class=\"problem\">" + esc(err) + "</p><p><a href=\"/\">Home</a></p>"), "text/html; charset=utf-8", null);
            } catch (Exception ignored) {
                // The response was already started.
            }
        }
    }

    private static void home(HttpExchange exchange) throws IOException {
        Session session = session(exchange);
        String problem = null;
        RelyingParty party = null;
        try {
            party = rp();
        } catch (Exception err) {
            problem = "The relying party is not configured yet: " + err + ". Run scripts/configure_iya_sts.py.";
        }
        if (session != null) {
            RelyingParty.Login login = session.login;
            String who = first(login.preferredUsername, login.email, login.subject);
            StringBuilder rows = new StringBuilder();
            row(rows, "Subject", login.subject);
            row(rows, "Issuer", login.issuer);
            row(rows, "Email", login.email);
            row(rows, "Name", login.name);
            row(rows, "Username", login.preferredUsername);
            String body = "<h1>Signed in as " + esc(who) + "</h1><table class=\"facts\">" + rows
                    + "</table><p><small>The access token and the refresh token stay in this process. This page does not show them.</small></p><p><small>Shared Signals: "
                    + esc(receiverState) + "</small></p><form method=\"post\" action=\"/logout\"><button type=\"submit\">Sign out</button></form>";
            send(exchange, 200, page("Signed in", body), "text/html; charset=utf-8", null);
            return;
        }
        String issuer = party == null ? "" : " of " + esc(party.metadata().get("issuer"));
        String problemHtml = problem == null ? "" : "<p class=\"problem\">" + esc(problem) + "</p>";
        String body = "<h1>Sign in with OpenID Connect</h1>" + problemHtml
                + "<p>This application is a confidential client" + issuer
                + ". It sends the browser to the authorization endpoint (Authorization Code, PKCE S256) and takes the tokens on the back channel.</p>"
                + "<p class=\"buttons\"><a class=\"button primary\" href=\"/login\">Sign in with OpenID Connect</a></p>";
        send(exchange, 200, page("Sign in", body), "text/html; charset=utf-8", null);
    }

    private static void login(HttpExchange exchange) throws IOException {
        RelyingParty.Transaction request = rp().authorize();
        Map<String, Object> txn = new LinkedHashMap<>();
        txn.put("state", request.state);
        txn.put("nonce", request.nonce);
        txn.put("codeVerifier", request.codeVerifier);
        txn.put("redirectUri", request.redirectUri);
        redirect(exchange, 302, request.url, List.of(cookie("oidc_txn", seal(txn), "/callback", 600)));
    }

    private static void callback(HttpExchange exchange) throws IOException {
        RelyingParty party = rp();
        Map<String, String> query = query(exchange.getRequestURI().getRawQuery());
        Map<String, Object> txn = unseal(cookies(exchange).get("oidc_txn"));
        String clear = cookie("oidc_txn", "", "/callback", 0);
        try {
            if (txn == null) throw new OidcError("validation", "this callback is not a sign-in this browser started");
            RelyingParty.Transaction transaction = new RelyingParty.Transaction();
            transaction.state = String.valueOf(txn.get("state"));
            transaction.nonce = String.valueOf(txn.get("nonce"));
            transaction.codeVerifier = String.valueOf(txn.get("codeVerifier"));
            transaction.redirectUri = String.valueOf(txn.get("redirectUri"));
            RelyingParty.Login login = party.complete(query, transaction);
            String sid = random();
            SESSIONS.put(sid, new Session(sid, login, System.currentTimeMillis() + 8L * 3600 * 1000));
            if (receiver != null) receiver.track(MemorySessionIndex.trackedFromLogin(sid, login, null));
            redirect(exchange, 303, "/", List.of(clear, cookie("oidc_session", sid, "/", 8 * 3600)));
        } catch (Exception err) {
            String what = err instanceof OidcError oidc ? oidc.code + ": " + oidc.getMessage() : String.valueOf(err);
            send(exchange, 400, page("Sign-in failed", "<h1>Sign-in failed</h1><p class=\"problem\">" + esc(what) + "</p><p><a href=\"/\">Start again</a></p>"),
                    "text/html; charset=utf-8", List.of(clear));
        }
    }

    private static void logout(HttpExchange exchange) throws IOException {
        Session session = session(exchange);
        if (session != null) {
            SESSIONS.remove(session.id);
            if (receiver != null) receiver.untrack(session.id);
        }
        redirect(exchange, 303, "/", List.of(cookie("oidc_session", "", "/", 0)));
    }

    private static RelyingParty rp() {
        if (rp != null) return rp;
        try {
            Map<String, Object> raw = loadRaw();
            applyRedirects(raw, port());
            if (raw.get("signals") == Boolean.FALSE) receiverState = "not configured (signals are off)";
            else if (!(raw.get("ssf") instanceof Map<?, ?> ssf) || ssf.get("transmitter") == null) {
                receiverState = "not configured (no ssf block in the configuration file)";
            } else receiverState = "starting";
            RelyingParty created = RelyingParty.create(Config.resolveConfig(raw, Path.of(configPath).toAbsolutePath().getParent().toString()));
            startReceiver(created);
            rp = created;
            return created;
        } catch (RuntimeException err) {
            rp = null;
            throw err;
        } catch (Exception err) {
            rp = null;
            throw new OidcError("config", String.valueOf(err), err);
        }
    }

    @SuppressWarnings("unchecked")
    private static void startReceiver(RelyingParty party) {
        if (party.config().get("signals") == Boolean.FALSE || !(party.config().get("ssf") instanceof Map<?, ?>)) {
            if (party.config().get("signals") == Boolean.FALSE) receiverState = "not configured (signals are off)";
            return;
        }
        if (receiver != null) return;
        Map<String, Object> ssf = (Map<String, Object>) party.config().get("ssf");
        long interval = ssf.get("pollIntervalMs") instanceof Number number && number.longValue() != 0 ? number.longValue() : 5000;
        SignalsReceiver created = SignalsReceiver.builder(String.valueOf(ssf.get("transmitter")), (ids, event) -> ids.forEach(SESSIONS::remove))
                .tls(party.tls())
                .headers(() -> Map.of("authorization", "Bearer " + party.clientCredentials("ssf.manage").accessToken))
                .description("oidc-caep-risc demo (" + party.config().get("clientId") + ")")
                .pollIntervalMs(interval)
                .build();
        receiver = created;
        try {
            created.start();
            receiverState = "polling stream " + created.stream().get("stream_id") + " at " + ssf.get("transmitter");
        } catch (Exception err) {
            receiver = null;
            receiverState = "not running: " + err;
            System.err.println("ssf: the receiver did not start: " + err);
        }
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> loadRaw() throws IOException {
        Map<String, Object> raw = Jsons.map(Jsons.read(Files.readString(Path.of(configPath))));
        if (raw == null) throw new OidcError("config", "the configuration must be a JSON object");
        String metadataFile = System.getenv("OIDC_METADATA_FILE");
        if (metadataFile != null && !metadataFile.isEmpty()) {
            raw.put("metadataFile", metadataFile);
            raw.remove("metadataUrl");
            raw.remove("issuer");
        }
        return raw;
    }

    private static void applyRedirects(Map<String, Object> raw, int port) {
        String publicValue = publicUrl != null ? publicUrl : System.getenv().getOrDefault("PUBLIC_URL", "");
        boolean given = publicUrl != null || (System.getenv("PUBLIC_URL") != null && !System.getenv("PUBLIC_URL").isEmpty());
        String redirect = String.valueOf(raw.get("redirectUri") != null ? raw.get("redirectUri") : raw.getOrDefault("redirect_uri", ""));
        String post = String.valueOf(raw.get("postLogoutRedirectUri") != null ? raw.get("postLogoutRedirectUri") : raw.getOrDefault("post_logout_redirect_uri", ""));
        Map<String, String> moved = redirectsFor(redirect, post, publicValue, given, port);
        if (raw.get("redirectUri") != null || raw.get("redirect_uri") == null) raw.put("redirectUri", moved.get("redirectUri"));
        else raw.put("redirect_uri", moved.get("redirectUri"));
        if (raw.get("postLogoutRedirectUri") != null || raw.get("post_logout_redirect_uri") != null || !post.isEmpty()) {
            if (raw.get("post_logout_redirect_uri") != null && raw.get("postLogoutRedirectUri") == null) raw.put("post_logout_redirect_uri", moved.get("postLogoutRedirectUri"));
            else raw.put("postLogoutRedirectUri", moved.get("postLogoutRedirectUri"));
        }
    }

    static String onPort(String url, int port) {
        URI uri;
        try {
            uri = URI.create(url);
        } catch (Exception err) {
            return url;
        }
        String host = uri.getHost();
        if (host == null || !("localhost".equals(host) || "127.0.0.1".equals(host) || "::1".equals(host))) return url;
        String hostname = host.contains(":") ? "[" + host + "]" : host;
        String path = uri.getRawPath() == null || uri.getRawPath().isEmpty() ? "/" : uri.getRawPath();
        String query = uri.getRawQuery() == null ? "" : "?" + uri.getRawQuery();
        String fragment = uri.getRawFragment() == null ? "" : "#" + uri.getRawFragment();
        return uri.getScheme() + "://" + hostname + ":" + port + path + query + fragment;
    }

    static Map<String, String> redirectsFor(String redirectUri, String postLogout, String publicUrl, boolean given, int port) {
        if (given && publicUrl != null && !publicUrl.isEmpty()) {
            URI base = URI.create(publicUrl.endsWith("/") ? publicUrl : publicUrl + "/");
            Map<String, String> out = new LinkedHashMap<>();
            out.put("redirectUri", move(base, redirectUri));
            out.put("postLogoutRedirectUri", move(base, postLogout));
            return out;
        }
        if (port > 0) return Map.of("redirectUri", onPort(redirectUri, port), "postLogoutRedirectUri", onPort(postLogout, port));
        return Map.of("redirectUri", redirectUri, "postLogoutRedirectUri", postLogout);
    }

    private static String move(URI base, String value) {
        URI next = URI.create(value);
        String host = base.getHost() == null ? "" : base.getHost();
        String hostname = host.contains(":") ? "[" + host + "]" : host;
        String netloc = base.getPort() < 0 ? hostname : hostname + ":" + base.getPort();
        String path = next.getRawPath() == null || next.getRawPath().isEmpty() ? "/" : next.getRawPath();
        String query = next.getRawQuery() == null ? "" : "?" + next.getRawQuery();
        String fragment = next.getRawFragment() == null ? "" : "#" + next.getRawFragment();
        return base.getScheme() + "://" + netloc + path + query + fragment;
    }

    private static int port() {
        String raw = System.getenv("PORT");
        if (raw == null || raw.isBlank()) return 3000;
        return Integer.parseInt(raw.trim());
    }

    private static Session session(HttpExchange exchange) {
        String sid = cookies(exchange).get("oidc_session");
        Session session = sid == null ? null : SESSIONS.get(sid);
        if (session == null) return null;
        if (session.expires <= System.currentTimeMillis()) {
            SESSIONS.remove(sid);
            return null;
        }
        return session;
    }

    private static Map<String, String> cookies(HttpExchange exchange) {
        Map<String, String> out = new LinkedHashMap<>();
        String header = exchange.getRequestHeaders().getFirst("cookie");
        if (header == null) return out;
        for (String part : header.split(";")) {
            int at = part.indexOf('=');
            if (at < 0) continue;
            out.put(part.substring(0, at).trim(), part.substring(at + 1).trim());
        }
        return out;
    }

    private static Map<String, String> query(String raw) {
        Map<String, String> out = new LinkedHashMap<>();
        if (raw == null || raw.isEmpty()) return out;
        for (String part : raw.split("&")) {
            int at = part.indexOf('=');
            String key = URLDecoder.decode(at < 0 ? part : part.substring(0, at), StandardCharsets.UTF_8);
            String value = URLDecoder.decode(at < 0 ? "" : part.substring(at + 1), StandardCharsets.UTF_8);
            out.put(key, value);
        }
        return out;
    }

    private static String cookie(String name, String value, String path, int maxAge) {
        StringBuilder out = new StringBuilder(name).append('=').append(value).append("; Path=").append(path).append("; HttpOnly; SameSite=Lax");
        if (secureCookies) out.append("; Secure");
        out.append("; Max-Age=").append(maxAge);
        return out.toString();
    }

    private static String seal(Object value) {
        String body = Base64.getUrlEncoder().withoutPadding().encodeToString(Jsons.write(value).getBytes(StandardCharsets.UTF_8));
        return body + "." + mac(body);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> unseal(String token) {
        if (token == null || !token.contains(".")) return null;
        String body = token.substring(0, token.indexOf('.'));
        String tag = token.substring(token.indexOf('.') + 1);
        if (!MessageDigest.isEqual(mac(body).getBytes(StandardCharsets.UTF_8), tag.getBytes(StandardCharsets.UTF_8))) return null;
        try {
            int mod = body.length() % 4;
            String padded = mod == 0 ? body : body + "====".substring(mod);
            return (Map<String, Object>) Jsons.read(new String(Base64.getUrlDecoder().decode(padded), StandardCharsets.UTF_8));
        } catch (Exception err) {
            return null;
        }
    }

    private static String mac(String value) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(SECRET, "HmacSHA256"));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(mac.doFinal(value.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception err) {
            throw new IllegalStateException(err);
        }
    }

    private static void send(HttpExchange exchange, int status, byte[] body, String type, List<String> cookies) throws IOException {
        Headers headers = exchange.getResponseHeaders();
        headers.set("content-type", type);
        headers.set("cache-control", "no-store");
        headers.set("referrer-policy", "no-referrer");
        headers.set("x-content-type-options", "nosniff");
        headers.set("x-frame-options", "DENY");
        headers.set("content-security-policy", "default-src 'none'; style-src 'self'; script-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'");
        if (cookies != null) cookies.forEach(cookie -> headers.add("set-cookie", cookie));
        exchange.sendResponseHeaders(status, body.length);
        exchange.getResponseBody().write(body);
        exchange.close();
    }

    private static void redirect(HttpExchange exchange, int status, String location, List<String> cookies) throws IOException {
        Headers headers = exchange.getResponseHeaders();
        headers.set("location", location);
        headers.set("cache-control", "no-store");
        headers.set("referrer-policy", "no-referrer");
        if (cookies != null) cookies.forEach(cookie -> headers.add("set-cookie", cookie));
        exchange.sendResponseHeaders(status, 0);
        exchange.close();
    }

    private static byte[] page(String title, String body) {
        String html = """
                <!doctype html>
                <html lang="en">
                <head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
                <title>%s</title><link rel="stylesheet" href="/styles.css"></head>
                <body><header><a href="/">oidc-caep-risc demo</a></header><main>
                %s
                </main><footer>A traditional web application signing in with OpenID Connect through oidc-caep-risc.</footer></body>
                </html>
                """.formatted(esc(title), body);
        return html.getBytes(StandardCharsets.UTF_8);
    }

    private static void row(StringBuilder rows, String name, String value) {
        if (value != null && !value.isEmpty()) rows.append("<tr><th>").append(esc(name)).append("</th><td>").append(esc(value)).append("</td></tr>");
    }

    private static String first(String... values) {
        for (String value : values) if (value != null && !value.isEmpty()) return value;
        return "";
    }

    private static String esc(Object value) {
        return String.valueOf(value == null ? "" : value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;");
    }

    private static String random() {
        byte[] buf = new byte[32];
        RANDOM.nextBytes(buf);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(buf);
    }

    private static byte[] secret() {
        String env = System.getenv("SESSION_SECRET");
        if (env != null && !env.isEmpty()) return env.getBytes(StandardCharsets.UTF_8);
        byte[] buf = new byte[32];
        new SecureRandom().nextBytes(buf);
        return buf;
    }

    private static final class Session {
        final String id;
        final RelyingParty.Login login;
        final long expires;

        Session(String id, RelyingParty.Login login, long expires) {
            this.id = id;
            this.login = login;
            this.expires = expires;
        }
    }
}
