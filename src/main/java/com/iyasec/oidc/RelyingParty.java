// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.oidc;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** A confidential OpenID Connect relying party. Tokens stay in this process. */
public final class RelyingParty {
    private static final List<String> FRONT = List.of("access_token", "id_token", "refresh_token", "token_type");

    private final Map<String, Object> config;
    private final Map<String, Object> metadata;
    private final PrivateKey key;
    private final List<String> algorithms;
    private List<Map<String, Object>> jwks;
    private final Map<String, Long> usedCodes = new LinkedHashMap<>();
    private CachedCredentials clientCredentials;

    private RelyingParty(Map<String, Object> config, Map<String, Object> metadata, PrivateKey key) {
        this.config = config;
        this.metadata = metadata;
        this.key = key;
        this.algorithms = Discovery.idTokenAlgorithms(list(metadata.get("id_token_signing_alg_values_supported")),
                config.get("idTokenSignedResponseAlg") == null ? null : String.valueOf(config.get("idTokenSignedResponseAlg")));
    }

    public Map<String, Object> config() {
        return config;
    }

    public Map<String, Object> metadata() {
        return metadata;
    }

    public static RelyingParty fromFile(String path) {
        return create(Config.readConfigFile(path));
    }

    public static RelyingParty create(Map<String, Object> config) {
        if (config == null) throw new OidcError("config", "the configuration must be a JSON object");
        String method = String.valueOf(config.get("tokenEndpointAuthMethod"));
        if ("private_key_jwt".equals(method) && !text(config.get("privateKeyPem"))) {
            throw new OidcError("config", "private_key_jwt needs a private key");
        }
        if (!"private_key_jwt".equals(method) && !text(config.get("clientSecret"))) {
            throw new OidcError("config", method + " needs a client secret");
        }
        Map<String, String> tls = tlsOf(config);
        if (config.get("allowInsecure") != Boolean.TRUE) {
            for (String[] pair : new String[][] {{"issuer", string(config.get("issuer"))}, {"metadataUrl", string(config.get("metadataUrl"))}}) {
                if (pair[1] != null && "http".equals(Discovery.scheme(pair[1])) && "issuer".equals(pair[0])) {
                    throw new OidcError("config", "issuer must use https (set allowInsecure for a development provider)");
                }
            }
        }
        @SuppressWarnings("unchecked")
        Map<String, Object> metadata = config.get("metadata") instanceof Map<?, ?> map ? (Map<String, Object>) map : null;
        if (metadata == null) {
            if (!text(config.get("metadataUrl"))) throw new OidcError("config", "metadataUrl or metadata is required");
            if (config.get("allowInsecure") != Boolean.TRUE && !"https".equals(Discovery.scheme(String.valueOf(config.get("metadataUrl"))))) {
                throw new OidcError("config", "metadataUrl must use https (set allowInsecure for a development provider)");
            }
            metadata = Discovery.discoverProvider(String.valueOf(config.get("metadataUrl")), tls);
        }
        if (config.get("allowInsecure") != Boolean.TRUE) {
            for (Map.Entry<String, Object> entry : metadata.entrySet()) {
                boolean http = entry.getValue() instanceof String text && text.startsWith("http:");
                String name = entry.getKey();
                if ((http && name.endsWith("endpoint")) || ("jwks_uri".equals(name) && http) || ("issuer".equals(name) && http)) {
                    throw new OidcError("discovery", name + " must use https: " + entry.getValue());
                }
            }
        }
        List<String> methods = strings(metadata.get("token_endpoint_auth_methods_supported"));
        if (!methods.isEmpty() && !methods.contains(method)) throw new OidcError("discovery", "the provider does not advertise " + method);
        List<String> challenges = strings(metadata.get("code_challenge_methods_supported"));
        if (!challenges.isEmpty() && !challenges.contains("S256")) throw new OidcError("discovery", "the provider does not advertise PKCE S256");
        PrivateKey key = text(config.get("privateKeyPem"))
                ? JwsCrypto.loadPrivateKey(String.valueOf(config.get("privateKeyPem")), config.get("privateKeyAlg") == null ? "RS256" : String.valueOf(config.get("privateKeyAlg")))
                : null;
        return new RelyingParty(config, metadata, key);
    }

    public Map<String, String> tls() {
        return tlsOf(config);
    }

    public Transaction authorize() {
        return authorize(null);
    }

    public Transaction authorize(AuthorizeOptions options) {
        AuthorizeOptions opts = options == null ? new AuthorizeOptions() : options;
        String redirectUri = opts.redirectUri == null ? String.valueOf(config.get("redirectUri")) : opts.redirectUri;
        String scope = opts.scope == null ? String.valueOf(config.get("scopes")) : opts.scope;
        String state = Codec.randomToken();
        String nonce = Codec.randomToken();
        String verifier = Codec.randomToken();
        Map<String, String> params = new LinkedHashMap<>();
        params.put("response_type", "code");
        params.put("client_id", String.valueOf(config.get("clientId")));
        params.put("redirect_uri", redirectUri);
        params.put("scope", scope);
        params.put("state", state);
        params.put("nonce", nonce);
        params.put("code_challenge", Codec.codeChallengeS256(verifier));
        params.put("code_challenge_method", "S256");
        if (text(opts.prompt)) params.put("prompt", opts.prompt);
        if (text(opts.loginHint)) params.put("login_hint", opts.loginHint);
        if (opts.maxAge != null) params.put("max_age", String.valueOf(opts.maxAge));
        if (text(opts.acrValues)) params.put("acr_values", opts.acrValues);
        Transaction transaction = new Transaction();
        transaction.state = state;
        transaction.nonce = nonce;
        transaction.codeVerifier = verifier;
        transaction.redirectUri = redirectUri;
        transaction.maxAge = opts.maxAge;
        transaction.expectedSub = text(opts.expectedSub) ? opts.expectedSub : null;
        String par = string(metadata.get("pushed_authorization_request_endpoint"));
        String mode = String.valueOf(config.get("par"));
        boolean usePar = "always".equals(mode) || ("auto".equals(mode) && par != null);
        if ("always".equals(mode) && par == null) {
            throw new OidcError("discovery", "par is always, and the provider has no pushed authorization endpoint");
        }
        if (usePar && par != null) {
            Map<String, Object> pushed = form(par, params);
            Object requestUri = pushed.get("request_uri");
            if (!(requestUri instanceof String uri) || uri.isEmpty()) {
                throw new OidcError("protocol", "the pushed authorization response has no request_uri");
            }
            transaction.url = withQuery(String.valueOf(metadata.get("authorization_endpoint")), Map.of(
                    "client_id", String.valueOf(config.get("clientId")),
                    "request_uri", uri));
            return transaction;
        }
        transaction.url = withQuery(String.valueOf(metadata.get("authorization_endpoint")), params);
        return transaction;
    }

    public Login complete(Map<String, ?> callback, Transaction transaction) {
        for (String name : FRONT) {
            if (has(callback, name)) {
                throw new OidcError("validation", name + " was returned on the redirect, and a code-flow client refuses it");
            }
        }
        if (has(callback, "error")) {
            String description = value(callback, "error_description");
            String error = value(callback, "error");
            String message = description == null ? error : error + ": " + description;
            throw new OidcError("protocol", message, null, error);
        }
        String state = value(callback, "state") == null ? "" : value(callback, "state");
        if (transaction == null || !text(transaction.state) || !same(state, transaction.state)) {
            throw new OidcError("validation", "the callback state does not match this sign-in");
        }
        if (callback != null && callback.containsKey("iss") && callback.get("iss") != null && !String.valueOf(metadata.get("issuer")).equals(String.valueOf(callback.get("iss")))) {
            throw new OidcError("validation", "iss mismatch in the callback: " + callback.get("iss"));
        }
        if ((callback == null || !callback.containsKey("iss") || callback.get("iss") == null)
                && metadata.get("authorization_response_iss_parameter_supported") == Boolean.TRUE) {
            throw new OidcError("validation", "iss is missing from the callback, and the provider requires it");
        }
        String code = value(callback, "code");
        if (code == null || code.isEmpty()) throw new OidcError("validation", "the callback has no code");
        rememberCode(code);
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("grant_type", "authorization_code");
        body.put("code", code);
        body.put("redirect_uri", transaction.redirectUri);
        body.put("code_verifier", transaction.codeVerifier);
        Map<String, Object> tokens = token(body);
        if (!(tokens.get("id_token") instanceof String)) throw new OidcError("protocol", "the token response has no id_token");
        Map<String, Object> extra = new LinkedHashMap<>();
        extra.put("nonce", transaction.nonce);
        extra.put("accessToken", tokens.get("access_token"));
        extra.put("code", code);
        if (transaction.maxAge != null) extra.put("maxAge", transaction.maxAge);
        Map<String, Object> claims = idToken(String.valueOf(tokens.get("id_token")), extra);
        if (text(transaction.expectedSub) && !transaction.expectedSub.equals(claims.get("sub"))) {
            throw new OidcError("validation", "the provider signed in a different account from the one requested");
        }
        return loginFrom(tokens, claims);
    }

    public Login refresh(String refreshToken, Login previous) {
        return refresh(refreshToken, null, previous);
    }

    public Login refresh(String refreshToken, String scope, Login previous) {
        if (!text(refreshToken)) throw new OidcError("protocol", "there is no refresh token");
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("grant_type", "refresh_token");
        body.put("refresh_token", refreshToken);
        if (text(scope)) body.put("scope", scope);
        Map<String, Object> tokens = token(copy(body));
        Map<String, Object> claims = previous == null ? null : previous.claims;
        String idToken = tokens.get("id_token") instanceof String signed ? signed : previous == null ? null : previous.idToken;
        if (tokens.get("id_token") instanceof String) {
            if (previous == null) {
                throw new OidcError("validation", "the refresh returned an ID token and there is no previous sign-in to check it against");
            }
            Map<String, Object> extra = new LinkedHashMap<>();
            extra.put("accessToken", tokens.get("access_token"));
            extra.put("previousSub", previous.subject);
            claims = idToken(String.valueOf(tokens.get("id_token")), extra);
            idToken = String.valueOf(tokens.get("id_token"));
        }
        if (claims == null || !text(idToken) || (previous == null && !(tokens.get("id_token") instanceof String))) {
            throw new OidcError("protocol", "the refresh returned no ID token and no previous sign-in was given");
        }
        Map<String, Object> merged = new LinkedHashMap<>(tokens);
        merged.put("refresh_token", tokens.get("refresh_token") instanceof String rotated ? rotated : refreshToken);
        merged.put("id_token", idToken);
        return loginFrom(merged, claims);
    }

    public Credentials clientCredentials() {
        return clientCredentials("ssf.manage");
    }

    public Credentials clientCredentials(String scope) {
        long now = System.currentTimeMillis();
        if (clientCredentials != null && clientCredentials.scope.equals(scope) && clientCredentials.until > now) {
            return clientCredentials.token;
        }
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("grant_type", "client_credentials");
        body.put("scope", scope);
        Credentials minted = credentialsFrom(token(body));
        long until = minted.expiresAt != null ? minted.expiresAt.getTime() - 30_000 : now + 60_000;
        clientCredentials = new CachedCredentials(scope, minted, until);
        return minted;
    }

    public Map<String, Object> userinfo(String accessToken, String expectedSub) {
        if (!text(expectedSub)) throw new OidcError("validation", "userinfo needs the subject to check the response against");
        if (!text(metadata.get("userinfo_endpoint"))) throw new OidcError("discovery", "the provider has no userinfo_endpoint");
        Http.Result answer = Http.send(String.valueOf(metadata.get("userinfo_endpoint")), "GET", Map.of(
                "accept", "application/json, application/jwt",
                "authorization", "Bearer " + accessToken), null, tls(), "protocol");
        if (answer.status() == 401) throw new OidcError("protocol", "userinfo refused the access token", null, "invalid_token");
        if (answer.status() != 200) throw new OidcError("protocol", "userinfo answered " + answer.status());
        Map<String, Object> claims;
        if (answer.contentType().contains("application/jwt")) {
            Map<String, Object> extra = new LinkedHashMap<>();
            extra.put("algorithms", algorithms);
            claims = idToken(answer.body().strip(), extra);
        } else {
            Object body;
            try {
                body = Jsons.read(answer.body());
            } catch (Exception err) {
                throw new OidcError("protocol", "userinfo did not answer JSON", err);
            }
            claims = Jsons.map(body);
            if (claims == null) throw new OidcError("validation", "userinfo did not answer a JSON object");
        }
        if (!expectedSub.equals(claims.get("sub"))) throw new OidcError("validation", "userinfo sub does not match the ID token sub");
        return claims;
    }

    public String endSessionUrl(String idToken, String state) {
        return endSessionUrl(idToken, null, state, null);
    }

    public String endSessionUrl(String idToken, String postLogoutRedirectUri, String state, String logoutHint) {
        if (!text(metadata.get("end_session_endpoint"))) return null;
        String redirect = text(postLogoutRedirectUri) ? postLogoutRedirectUri : string(config.get("postLogoutRedirectUri"));
        Map<String, String> query = new LinkedHashMap<>();
        if (text(idToken)) query.put("id_token_hint", idToken);
        if (text(redirect)) query.put("post_logout_redirect_uri", redirect);
        query.put("client_id", String.valueOf(config.get("clientId")));
        if (text(logoutHint)) query.put("logout_hint", logoutHint);
        if (text(state)) query.put("state", state);
        return withQuery(String.valueOf(metadata.get("end_session_endpoint")), query);
    }

    private Map<String, Object> idToken(String token, Map<String, Object> extra) {
        Map<String, Object> checks = new LinkedHashMap<>();
        checks.put("issuer", metadata.get("issuer"));
        checks.put("clientId", config.get("clientId"));
        checks.put("algorithms", extra.get("algorithms") == null ? algorithms : extra.get("algorithms"));
        checks.put("jwks", keys(false));
        checks.put("clockToleranceSec", config.get("clockToleranceSec"));
        checks.put("maxIdTokenAgeSec", config.get("maxIdTokenAgeSec"));
        if (text(config.get("clientSecret"))) checks.put("clientSecret", config.get("clientSecret"));
        for (Map.Entry<String, Object> entry : extra.entrySet()) {
            if (!"algorithms".equals(entry.getKey())) checks.put(entry.getKey(), entry.getValue());
        }
        try {
            return IdToken.validate(token, checks);
        } catch (OidcError err) {
            if (!"signature".equals(err.code)) throw err;
            jwks = null;
            checks.put("jwks", keys(true));
            return IdToken.validate(token, checks);
        }
    }

    private List<Map<String, Object>> keys(boolean force) {
        if (!force && jwks != null) return jwks;
        jwks = IdToken.fetchJwks(String.valueOf(metadata.get("jwks_uri")), tls());
        return jwks;
    }

    private Map<String, Object> copy(Map<String, ?> body) {
        return new LinkedHashMap<>(body);
    }

    private Map<String, Object> token(Map<String, ?> body) {
        Map<String, Object> parsed = form(String.valueOf(metadata.get("token_endpoint")), body);
        if (!(parsed.get("access_token") instanceof String access) || access.isEmpty()) {
            throw new OidcError("protocol", "the token response has no access_token");
        }
        if (!(parsed.get("token_type") instanceof String tokenType) || tokenType.isEmpty()) {
            throw new OidcError("protocol", "the token response has no token_type");
        }
        if ("dpop".equalsIgnoreCase(tokenType)) {
            throw new OidcError("protocol", "the provider returned a DPoP token; this client asked for a Bearer token");
        }
        if (!"bearer".equalsIgnoreCase(tokenType)) throw new OidcError("protocol", "the token response token_type is " + tokenType);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("access_token", access);
        out.put("token_type", tokenType);
        if (parsed.get("id_token") instanceof String id) out.put("id_token", id);
        if (parsed.get("refresh_token") instanceof String refresh) out.put("refresh_token", refresh);
        if (parsed.get("expires_in") instanceof Number expires) out.put("expires_in", expires);
        if (parsed.get("scope") instanceof String scope) out.put("scope", scope);
        return out;
    }

    private Map<String, Object> form(String url, Map<String, ?> body) {
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("accept", "application/json");
        headers.put("content-type", "application/x-www-form-urlencoded");
        Map<String, Object> fields = new LinkedHashMap<>(body);
        ClientAuth.apply(config, key, fields, headers, String.valueOf(metadata.get("issuer")));
        Http.Result answer = Http.send(url, "POST", headers, Codec.formBody(fields).getBytes(StandardCharsets.UTF_8), tls(), "protocol");
        Object parsed;
        try {
            parsed = answer.body() == null || answer.body().isEmpty() ? Map.of() : Jsons.read(answer.body());
        } catch (Exception err) {
            throw new OidcError("protocol", url + " answered " + answer.status() + " with no JSON", err);
        }
        Map<String, Object> doc = Jsons.map(parsed);
        if (doc == null) doc = new LinkedHashMap<>();
        if (answer.status() != 200 && answer.status() != 201) {
            String oauth = doc.get("error") instanceof String text ? text : null;
            String description = doc.get("error_description") instanceof String text ? text : "";
            String message = url + " answered " + answer.status();
            if (oauth != null) message += ": " + oauth;
            if (!description.isEmpty()) message += ": " + description;
            throw new OidcError("protocol", message, null, oauth);
        }
        return doc;
    }

    private void rememberCode(String code) {
        long now = System.currentTimeMillis() / 1000;
        long cutoff = now - 10 * 60;
        synchronized (usedCodes) {
            usedCodes.entrySet().removeIf(entry -> entry.getValue() < cutoff);
            String digest = Codec.hex(Codec.sha256(code.getBytes(StandardCharsets.UTF_8)));
            if (usedCodes.containsKey(digest)) throw new OidcError("validation", "this authorization code was already used");
            usedCodes.put(digest, now);
        }
    }

    private static Login loginFrom(Map<String, Object> tokens, Map<String, Object> claims) {
        Login login = new Login();
        login.subject = String.valueOf(claims.get("sub"));
        login.issuer = String.valueOf(claims.get("iss"));
        login.claims = claims;
        login.accessToken = String.valueOf(tokens.get("access_token"));
        login.idToken = tokens.get("id_token") instanceof String id ? id : "";
        login.tokenType = String.valueOf(tokens.get("token_type"));
        login.email = claim(claims, "email");
        login.name = claim(claims, "name");
        login.preferredUsername = claim(claims, "preferred_username");
        login.sid = claim(claims, "sid");
        if (tokens.get("refresh_token") instanceof String refresh) login.refreshToken = refresh;
        if (tokens.get("expires_in") instanceof Number expires) {
            login.expiresAt = new Date(System.currentTimeMillis() + (long) (expires.doubleValue() * 1000));
        }
        if (tokens.get("scope") instanceof String scope) login.scope = scope;
        return login;
    }

    private static Credentials credentialsFrom(Map<String, Object> tokens) {
        Credentials out = new Credentials();
        out.accessToken = String.valueOf(tokens.get("access_token"));
        out.tokenType = String.valueOf(tokens.get("token_type"));
        if (tokens.get("expires_in") instanceof Number expires) {
            out.expiresAt = new Date(System.currentTimeMillis() + (long) (expires.doubleValue() * 1000));
        }
        if (tokens.get("scope") instanceof String scope) out.scope = scope;
        return out;
    }

    private static String withQuery(String base, Map<String, String> params) {
        URI uri = URI.create(base);
        String path = uri.getRawPath() == null || uri.getRawPath().isEmpty() ? "/" : uri.getRawPath();
        return uri.getScheme() + "://" + uri.getRawAuthority() + path + "?" + Codec.formBody(params);
    }

    private static Map<String, String> tlsOf(Map<String, Object> config) {
        if (!text(config.get("tlsCa"))) return Map.of();
        return Map.of("ca", String.valueOf(config.get("tlsCa")));
    }

    private static String claim(Map<String, Object> claims, String name) {
        return claims.get(name) instanceof String text && !text.isEmpty() ? text : null;
    }

    private static boolean has(Map<String, ?> query, String name) {
        return query != null && query.containsKey(name) && query.get(name) != null;
    }

    private static String value(Map<String, ?> query, String name) {
        if (!has(query, name)) return null;
        return String.valueOf(query.get(name));
    }

    private static boolean same(String left, String right) {
        if (left == null || right == null) return false;
        return MessageDigest.isEqual(left.getBytes(StandardCharsets.UTF_8), right.getBytes(StandardCharsets.UTF_8));
    }

    private static boolean text(Object value) {
        return value instanceof String text && !text.isEmpty();
    }

    private static String string(Object value) {
        return value instanceof String text && !text.isEmpty() ? text : null;
    }

    private static List<String> strings(Object value) {
        List<String> out = new ArrayList<>();
        if (value instanceof List<?> items) for (Object item : items) out.add(String.valueOf(item));
        return out;
    }

    private static List<?> list(Object value) {
        return value instanceof List<?> items ? items : List.of();
    }

    public static class Transaction {
        public String url;
        public String state;
        public String nonce;
        public String codeVerifier;
        public String redirectUri;
        public Integer maxAge;
        public String expectedSub;
    }

    public static class AuthorizeOptions {
        public String redirectUri;
        public String scope;
        public String prompt;
        public String loginHint;
        public Integer maxAge;
        public String acrValues;
        public String expectedSub;
    }

    public static class Login {
        public String subject;
        public String issuer;
        public Map<String, Object> claims;
        public String accessToken;
        public String idToken;
        public String tokenType;
        public String email;
        public String name;
        public String preferredUsername;
        public String sid;
        public String refreshToken;
        public Date expiresAt;
        public String scope;
    }

    public static class Credentials {
        public String accessToken;
        public String tokenType;
        public Date expiresAt;
        public String scope;
    }

    private record CachedCredentials(String scope, Credentials token, long until) {}
}
