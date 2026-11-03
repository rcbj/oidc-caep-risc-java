// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.oidc;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

/** Configuration. JSON keys are the same names the Node library reads. */
public final class Config {
    public static final List<String> AUTH_METHODS = List.of("client_secret_basic", "client_secret_post", "private_key_jwt");
    static Function<String, String> environment = System::getenv;

    private Config() {}

    public static Map<String, Object> readConfigFile(String path) {
        Path file = Path.of(path);
        Object raw;
        try {
            raw = Jsons.read(Files.readString(file));
        } catch (Exception err) {
            Caught.error(err);
            throw new OidcError("config", "could not read " + path + ": " + err, err);
        }
        return resolveConfig(raw, file.toAbsolutePath().getParent().toString());
    }

    public static Map<String, Object> resolveConfig(Object raw, String baseDir) {
        Map<String, Object> doc = object(raw);
        String clientId = text(doc.containsKey("clientId") && doc.get("clientId") != null ? doc.get("clientId") : doc.get("client_id")).trim();
        if (clientId.isEmpty()) throw new OidcError("config", "client_id is required");
        Object methodRaw = doc.get("tokenEndpointAuthMethod");
        String method = methodRaw == null || String.valueOf(methodRaw).isEmpty() ? "client_secret_basic" : String.valueOf(methodRaw);
        if ("none".equals(method)) {
            throw new OidcError("config", "tokenEndpointAuthMethod \"none\" is a public client; this library authenticates a confidential client");
        }
        if (!AUTH_METHODS.contains(method)) {
            throw new OidcError("config", "tokenEndpointAuthMethod must be " + String.join(", ", AUTH_METHODS) + ", not " + method);
        }
        String redirectUri = text(doc.containsKey("redirectUri") && doc.get("redirectUri") != null ? doc.get("redirectUri") : doc.get("redirect_uri")).trim();
        if (redirectUri.isEmpty()) throw new OidcError("config", "redirectUri is required");
        boolean allowInsecure = doc.get("allowInsecure") == Boolean.TRUE;
        boolean signalsPresent = doc.containsKey("signals");
        boolean signals = signalsOn(signalsPresent ? doc.get("signals") : null);
        String scopes;
        if (!doc.containsKey("scopes") || doc.get("scopes") == null) scopes = Discovery.DEFAULT_SCOPES.trim();
        else if (doc.get("scopes") instanceof List<?> items) scopes = joinScopes(items);
        else scopes = text(doc.get("scopes")).trim();
        if (!signals) {
            List<String> kept = new ArrayList<>();
            for (String part : scopes.split(" ")) if (!part.isEmpty() && !"ssf.read".equals(part) && !"ssf.manage".equals(part)) kept.add(part);
            scopes = String.join(" ", kept);
        }
        boolean openid = false;
        for (String part : scopes.split(" ")) if ("openid".equals(part)) openid = true;
        if (!openid) throw new OidcError("config", "scopes must include openid");
        String par = mode(doc.get("par"), "par");
        String dpop = mode(doc.get("dpop"), "dpop");
        String issuer = doc.get("issuer") == null ? null : text(doc.get("issuer")).trim();
        if (issuer != null && issuer.isEmpty()) issuer = null;
        String metadataUrl = doc.get("metadataUrl") == null ? null : text(doc.get("metadataUrl")).trim();
        if (metadataUrl != null && metadataUrl.isEmpty()) metadataUrl = null;
        if (metadataUrl != null) {
            String fromUrl = Discovery.issuerFromMetadataUrl(metadataUrl);
            if (issuer != null && !issuer.equals(fromUrl)) {
                throw new OidcError("config", "issuer " + issuer + " is not the issuer of " + metadataUrl + " (" + fromUrl + ")");
            }
            issuer = fromUrl;
        }
        Map<String, Object> metadata = null;
        if (doc.get("metadataFile") != null) {
            Path full = Path.of(baseDir).resolve(String.valueOf(doc.get("metadataFile"))).normalize();
            if (Path.of(String.valueOf(doc.get("metadataFile"))).isAbsolute()) full = Path.of(String.valueOf(doc.get("metadataFile")));
            Object body;
            try {
                body = Jsons.read(Files.readString(full));
            } catch (Exception err) {
                Caught.error(err);
                throw new OidcError("config", "could not read metadata at " + full + ": " + err, err);
            }
            metadata = Discovery.validateProviderMetadata(body, issuer);
            issuer = String.valueOf(metadata.get("issuer"));
        }
        if (metadataUrl == null && metadata == null) throw new OidcError("config", "metadataUrl or metadataFile is required");
        boolean needsSecret = !"private_key_jwt".equals(method);
        String clientSecret = null;
        if (truthy(doc.get("clientSecret"))) clientSecret = secretValue(String.valueOf(doc.get("clientSecret")), baseDir, "the client secret");
        if (needsSecret && (clientSecret == null || clientSecret.isEmpty())) throw new OidcError("config", method + " needs clientSecret");
        String privateKeyPem = null;
        if (truthy(doc.get("privateKey"))) privateKeyPem = keyValue(String.valueOf(doc.get("privateKey")), baseDir, "the private key");
        if ("private_key_jwt".equals(method) && (privateKeyPem == null || privateKeyPem.isEmpty())) {
            throw new OidcError("config", "private_key_jwt needs privateKey");
        }
        String dpopKey = null;
        if (truthy(doc.get("dpopKey"))) dpopKey = keyValue(String.valueOf(doc.get("dpopKey")), baseDir, "the DPoP key");
        String tlsCa = readTrust(doc.get("tlsCa"), baseDir);
        Object postRaw = doc.containsKey("postLogoutRedirectUri") ? doc.get("postLogoutRedirectUri") : doc.get("post_logout_redirect_uri");
        String postLogout = text(postRaw).trim();
        Map<String, Object> ssf = null;
        Map<String, Object> ssfDoc = Jsons.map(doc.get("ssf"));
        if (signals && ssfDoc != null && truthy(ssfDoc.get("transmitter"))) {
            String transmitter = String.valueOf(ssfDoc.get("transmitter")).replaceAll("/+$", "");
            if (!transmitter.startsWith("http://") && !transmitter.startsWith("https://")) {
                throw new OidcError("config", "ssf.transmitter must be an http(s) URL");
            }
            ssf = new LinkedHashMap<>();
            ssf.put("transmitter", transmitter);
            if (truthy(ssfDoc.get("pollIntervalMs"))) ssf.put("pollIntervalMs", ssfDoc.get("pollIntervalMs"));
        }
        Map<String, Object> out = new LinkedHashMap<>();
        if (issuer != null) out.put("issuer", issuer);
        if (metadataUrl != null) out.put("metadataUrl", metadataUrl);
        if (metadata != null) out.put("metadata", metadata);
        out.put("clientId", clientId);
        if (clientSecret != null && !clientSecret.isEmpty()) out.put("clientSecret", clientSecret);
        if (privateKeyPem != null && !privateKeyPem.isEmpty()) out.put("privateKeyPem", privateKeyPem);
        out.put("privateKeyAlg", truthy(doc.get("privateKeyAlg")) ? doc.get("privateKeyAlg") : "RS256");
        out.put("tokenEndpointAuthMethod", method);
        out.put("redirectUri", checkRedirect(redirectUri, "redirectUri"));
        if (!postLogout.isEmpty()) out.put("postLogoutRedirectUri", checkRedirect(postLogout, "postLogoutRedirectUri"));
        out.put("scopes", scopes);
        if (truthy(doc.get("idTokenSignedResponseAlg"))) out.put("idTokenSignedResponseAlg", doc.get("idTokenSignedResponseAlg"));
        out.put("idTokenSigningAlgs", signingAlgs(doc.get("idTokenSigningAlgs")));
        out.put("requireIdTokenTypAndAtHash", flag(doc.get("requireIdTokenTypAndAtHash"), "requireIdTokenTypAndAtHash", true));
        String acr = acrValues(doc.get("acrValues"));
        if (acr != null) out.put("acrValues", acr);
        out.put("par", par);
        out.put("dpop", dpop);
        if (dpopKey != null && !dpopKey.isEmpty()) out.put("dpopKey", dpopKey);
        out.put("clockToleranceSec", seconds(doc.get("clockToleranceSec"), "clockToleranceSec", 30));
        out.put("maxIdTokenAgeSec", seconds(doc.get("maxIdTokenAgeSec"), "maxIdTokenAgeSec", 600));
        out.put("allowInsecure", allowInsecure);
        if (tlsCa != null && !tlsCa.isEmpty()) out.put("tlsCa", tlsCa);
        if (!signals) out.put("signals", Boolean.FALSE);
        if (ssf != null) out.put("ssf", ssf);
        return out;
    }

    /**
     * Applies the defaults and the checks of {@link #resolveConfig} to a
     * configuration map that did not come from a file, so a relying party
     * created directly holds the same rules: {@code par} and {@code dpop}
     * ({@code auto}), {@code clockToleranceSec} (30), {@code maxIdTokenAgeSec}
     * (600), {@code idTokenSigningAlgs} ({@code ["RS256"]}),
     * {@code requireIdTokenTypAndAtHash} (true), and the redirect-URI rule.
     * Applying it twice gives the same map.
     *
     * @param given the configuration
     * @return a new map with the defaults filled in
     */
    public static Map<String, Object> normalize(Map<String, Object> given) {
        if (given == null) throw new OidcError("config", "the configuration must be a JSON object");
        Map<String, Object> out = new LinkedHashMap<>(given);
        out.put("par", mode(given.get("par"), "par"));
        out.put("dpop", mode(given.get("dpop"), "dpop"));
        out.put("clockToleranceSec", seconds(given.get("clockToleranceSec"), "clockToleranceSec", 30));
        out.put("maxIdTokenAgeSec", seconds(given.get("maxIdTokenAgeSec"), "maxIdTokenAgeSec", 600));
        out.put("idTokenSigningAlgs", signingAlgs(given.get("idTokenSigningAlgs")));
        out.put("requireIdTokenTypAndAtHash", flag(given.get("requireIdTokenTypAndAtHash"), "requireIdTokenTypAndAtHash", true));
        String acr = acrValues(given.get("acrValues"));
        if (acr == null) out.remove("acrValues");
        else out.put("acrValues", acr);
        if (truthy(given.get("dpopKey"))) {
            String raw = String.valueOf(given.get("dpopKey"));
            out.put("dpopKey", raw.contains("-----BEGIN") ? raw : keyValue(raw, Path.of("").toAbsolutePath().toString(), "the DPoP key"));
        } else {
            out.remove("dpopKey");
        }
        String redirect = given.get("redirectUri") == null ? "" : String.valueOf(given.get("redirectUri")).trim();
        if (redirect.isEmpty()) throw new OidcError("config", "redirectUri is required");
        out.put("redirectUri", checkRedirect(redirect, "redirectUri"));
        if (given.get("postLogoutRedirectUri") instanceof String post && !post.isBlank()) {
            out.put("postLogoutRedirectUri", checkRedirect(post.trim(), "postLogoutRedirectUri"));
        }
        return out;
    }

    /**
     * The redirect-URI rule: https, or http on a loopback host
     * ({@code localhost}, {@code 127.0.0.1}, {@code [::1]}).
     *
     * @param value the URI
     * @param name the setting or option the URI came from, for the error
     * @return the URI, unchanged
     */
    public static String checkRedirect(String value, String name) {
        URIParts parts = URIParts.of(value);
        if (parts == null || (!"http".equals(parts.scheme) && !"https".equals(parts.scheme)) || parts.host == null || parts.host.isEmpty()) {
            throw new OidcError("config", name + " is not a URL: " + value);
        }
        if ("https".equals(parts.scheme)) return value;
        if (loopback(parts.host)) return value;
        throw new OidcError("config", name + " must use https, or http on loopback: " + value);
    }

    private static String mode(Object raw, String name) {
        String value = raw == null ? "auto" : String.valueOf(raw);
        if (!"auto".equals(value) && !"always".equals(value) && !"never".equals(value)) {
            throw new OidcError("config", name + " must be auto, always, or never");
        }
        return value;
    }

    private static Object seconds(Object raw, String name, int fallback) {
        if (raw == null) return fallback;
        if (!(raw instanceof Number number) || number.doubleValue() < 0) {
            throw new OidcError("config", name + " must be a number of seconds, not " + raw);
        }
        return number;
    }

    private static boolean flag(Object raw, String name, boolean fallback) {
        if (raw == null) return fallback;
        if (raw instanceof Boolean value) return value;
        throw new OidcError("config", name + " must be true or false");
    }

    private static List<String> signingAlgs(Object raw) {
        List<String> names = new ArrayList<>();
        if (raw == null) {
            names.add("RS256");
        } else if (raw instanceof List<?> items) {
            for (Object item : items) if (item != null && !String.valueOf(item).isBlank()) names.add(String.valueOf(item).trim());
        } else if (raw instanceof String text) {
            for (String part : text.split("[\\s,]+")) if (!part.isEmpty()) names.add(part);
        } else {
            throw new OidcError("config", "idTokenSigningAlgs must be a list of algorithm names");
        }
        if (names.isEmpty()) throw new OidcError("config", "idTokenSigningAlgs is empty");
        for (String name : names) {
            if ("none".equalsIgnoreCase(name)) throw new OidcError("config", "idTokenSigningAlgs must not name none; an unsigned ID token is never accepted");
            if (JwsCrypto.alg(name) == null) throw new OidcError("config", "idTokenSigningAlgs names " + name + ", which this library cannot verify");
        }
        return List.copyOf(names);
    }

    private static String acrValues(Object raw) {
        if (raw == null) return null;
        String joined = raw instanceof List<?> items ? joinScopes(items) : String.valueOf(raw).trim().replaceAll("\\s+", " ");
        return joined.isEmpty() ? null : joined;
    }

    private static boolean signalsOn(Object value) {
        if (value == null || value == Boolean.TRUE) return true;
        if (value == Boolean.FALSE) return false;
        throw new OidcError("config", "signals must be true or false");
    }

    private static String joinScopes(List<?> items) {
        List<String> parts = new ArrayList<>();
        for (Object item : items) {
            String part = String.valueOf(item).trim();
            if (!part.isEmpty()) parts.add(part);
        }
        return String.join(" ", parts);
    }

    private static String secretValue(String raw, String baseDir, String what) {
        if (raw.startsWith("env:")) {
            String name = raw.substring(4);
            String value = environment.apply(name);
            if (value == null || value.isEmpty()) throw new OidcError("config", what + " reads " + name + ", and that variable is empty");
            return value;
        }
        if (raw.startsWith("file:")) return readPath(raw.substring(5), baseDir, what);
        return raw;
    }

    private static String keyValue(String raw, String baseDir, String what) {
        if (raw.startsWith("env:") || raw.startsWith("file:") || raw.contains("-----BEGIN")) return secretValue(raw, baseDir, what);
        return readPath(raw, baseDir, what);
    }

    private static String readPath(String path, String baseDir, String what) {
        Path full = Path.of(path).isAbsolute() ? Path.of(path) : Path.of(baseDir).resolve(path);
        try {
            return Files.readString(full).strip();
        } catch (Exception err) {
            Caught.error(err);
            throw new OidcError("config", "could not read " + what + " at " + full + ": " + err, err);
        }
    }

    private static String readTrust(Object raw, String baseDir) {
        if (raw == null) return null;
        String value = String.valueOf(raw).strip();
        if (value.isEmpty()) return null;
        if (value.contains("-----BEGIN")) return value;
        if (value.startsWith("env:")) {
            String found = environment.apply(value.substring(4));
            return found == null || found.isEmpty() ? null : found;
        }
        String path = value.startsWith("file:") ? value.substring(5) : value;
        Path full = Path.of(path).isAbsolute() ? Path.of(path) : Path.of(baseDir).resolve(path);
        try {
            return Files.readString(full);
        } catch (IOException err) {
            Caught.warn(err);
            return null;
        }
    }

    private static boolean loopback(String host) {
        return "localhost".equals(host) || "127.0.0.1".equals(host) || "::1".equals(host) || "[::1]".equals(host);
    }

    private static boolean truthy(Object value) {
        if (value == null || value == Boolean.FALSE) return false;
        if (value instanceof String text) return !text.isEmpty();
        if (value instanceof Number number) return number.doubleValue() != 0;
        return true;
    }

    private static String text(Object value) {
        return value == null ? "" : String.valueOf(value);
    }

    private static Map<String, Object> object(Object raw) {
        Map<String, Object> doc = Jsons.map(raw);
        if (doc == null) throw new OidcError("config", "the configuration must be a JSON object");
        return doc;
    }

    private record URIParts(String scheme, String host) {
        static URIParts of(String value) {
            try {
                java.net.URI uri = new java.net.URI(value);
                return new URIParts(uri.getScheme(), uri.getHost());
            } catch (Exception err) {
                Caught.warn(err);
                return null;
            }
        }
    }
}
