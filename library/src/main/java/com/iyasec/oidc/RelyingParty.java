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
import java.util.concurrent.ConcurrentHashMap;

import com.iyasec.oidc.ssf.SignalsReceiver;

/** A confidential OpenID Connect relying party. Tokens stay in this process. */
public final class RelyingParty {
    private static final List<String> FRONT = List.of("access_token", "id_token", "refresh_token", "token_type");
    /** A cached session access token is used while it has more than this many milliseconds left. */
    public static final long SESSION_TOKEN_MARGIN_MS = 30_000;

    private final Map<String, Object> config;
    private final Map<String, Object> metadata;
    private final PrivateKey key;
    private final List<String> algorithms;
    private List<Map<String, Object>> jwks;
    private final Map<String, Long> usedCodes = new LinkedHashMap<>();
    private volatile CachedCredentials clientCredentials;
    private final Dpop dpop;
    private volatile SessionStore sessions = new MemorySessionStore();
    private final Map<String, Object> sessionLocks = new ConcurrentHashMap<>();

    private RelyingParty(Map<String, Object> config, Map<String, Object> metadata, PrivateKey key, Dpop dpop) {
        this.config = config;
        this.metadata = metadata;
        this.key = key;
        this.dpop = dpop;
        this.algorithms = Discovery.idTokenAlgorithms(list(metadata.get("id_token_signing_alg_values_supported")),
                config.get("idTokenSignedResponseAlg") == null ? null : String.valueOf(config.get("idTokenSignedResponseAlg")),
                strings(config.get("idTokenSigningAlgs")));
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

    /**
     * Creates a relying party from a configuration map. The defaults and
     * checks a configuration file gets ({@link Config#normalize}) apply here
     * too.
     *
     * @param given the configuration
     * @return the relying party
     */
    public static RelyingParty create(Map<String, Object> given) {
        if (given == null) throw new OidcError("config", "the configuration must be a JSON object");
        Map<String, Object> config = Config.normalize(given);
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
        boolean parRequired = metadata.get("require_pushed_authorization_requests") == Boolean.TRUE;
        String parMode = String.valueOf(config.get("par"));
        if (parRequired && "never".equals(parMode)) {
            throw new OidcError("config", "par is never, and the provider requires pushed authorization requests");
        }
        if (("always".equals(parMode) || parRequired) && !text(metadata.get("pushed_authorization_request_endpoint"))) {
            throw new OidcError("discovery", "pushed authorization requests are required, and the provider has no pushed authorization endpoint");
        }
        PrivateKey key = text(config.get("privateKeyPem"))
                ? JwsCrypto.loadPrivateKey(String.valueOf(config.get("privateKeyPem")), config.get("privateKeyAlg") == null ? "RS256" : String.valueOf(config.get("privateKeyAlg")))
                : null;
        return new RelyingParty(config, metadata, key, dpopFor(config, metadata));
    }

    private static Dpop dpopFor(Map<String, Object> config, Map<String, Object> metadata) {
        String mode = String.valueOf(config.get("dpop"));
        if ("never".equals(mode)) return null;
        boolean advertised = metadata.get("dpop_signing_alg_values_supported") instanceof List<?>;
        List<String> algs = strings(metadata.get("dpop_signing_alg_values_supported"));
        if (!advertised || !algs.contains(Dpop.ALG)) {
            if ("always".equals(mode)) {
                throw new OidcError("discovery", advertised
                        ? "dpop is always, and the provider does not accept ES256 proofs (" + String.join(", ", algs) + ")"
                        : "dpop is always, and the provider does not advertise dpop_signing_alg_values_supported");
            }
            return null;
        }
        return text(config.get("dpopKey")) ? Dpop.fromPem(String.valueOf(config.get("dpopKey"))) : Dpop.generate();
    }

    /**
     * Whether this relying party sends DPoP proofs (RFC 9449).
     *
     * @return true when DPoP is in use
     */
    public boolean usesDpop() {
        return dpop != null;
    }

    /**
     * The DPoP signer, when DPoP is in use.
     *
     * @return the signer, or null
     */
    public Dpop dpop() {
        return dpop;
    }

    /**
     * The store the sign-in token cache uses.
     *
     * @return the store
     */
    public SessionStore sessionStore() {
        return sessions;
    }

    /**
     * Replaces the sign-in token cache's store, for example with one shared
     * by several processes. Sessions in the earlier store are not copied.
     *
     * @param store the new store
     * @return this relying party
     */
    public RelyingParty sessionStore(SessionStore store) {
        if (store == null) throw new OidcError("config", "the session store must not be null");
        this.sessions = store;
        return this;
    }

    public Map<String, String> tls() {
        return tlsOf(config);
    }

    public Transaction authorize() {
        return authorize(null);
    }

    public Transaction authorize(AuthorizeOptions options) {
        AuthorizeOptions opts = options == null ? new AuthorizeOptions() : options;
        String redirectUri = opts.redirectUri == null ? String.valueOf(config.get("redirectUri")) : Config.checkRedirect(opts.redirectUri, "redirectUri");
        String acrValues = text(opts.acrValues) ? opts.acrValues.trim().replaceAll("\\s+", " ") : string(config.get("acrValues"));
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
        if (text(acrValues)) params.put("acr_values", acrValues);
        if (dpop != null) params.put("dpop_jkt", dpop.thumbprint());
        Transaction transaction = new Transaction();
        transaction.state = state;
        transaction.nonce = nonce;
        transaction.codeVerifier = verifier;
        transaction.redirectUri = redirectUri;
        transaction.maxAge = opts.maxAge;
        transaction.expectedSub = text(opts.expectedSub) ? opts.expectedSub : null;
        transaction.acrValues = text(acrValues) ? acrValues : null;
        String par = string(metadata.get("pushed_authorization_request_endpoint"));
        String mode = String.valueOf(config.get("par"));
        boolean required = metadata.get("require_pushed_authorization_requests") == Boolean.TRUE;
        boolean usePar = "always".equals(mode) || ("auto".equals(mode) && (par != null || required));
        if (usePar && par == null) {
            throw new OidcError("discovery", "pushed authorization requests are required, and the provider has no pushed authorization endpoint");
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

    /**
     * Completes a sign-in and keeps its tokens in the session cache under a
     * new random handle, returned as {@link Login#sessionId}.
     *
     * @param callback the query parameters of the redirect back
     * @param transaction the transaction {@link #authorize()} returned
     * @return the sign-in
     */
    public Login complete(Map<String, ?> callback, Transaction transaction) {
        return complete(callback, transaction, null);
    }

    /**
     * Completes a sign-in and keeps its tokens in the session cache under the
     * application's session identifier.
     *
     * @param callback the query parameters of the redirect back
     * @param transaction the transaction {@link #authorize()} returned
     * @param sessionId the application's session identifier, or null for a
     *        new random handle
     * @return the sign-in; {@link Login#sessionId} names its cache entry
     */
    public Login complete(Map<String, ?> callback, Transaction transaction, String sessionId) {
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
        if (text(transaction.acrValues)) {
            List<String> requested = List.of(transaction.acrValues.trim().split("\\s+"));
            if (!(claims.get("acr") instanceof String acr) || acr.isEmpty()) {
                throw new OidcError("validation", "acr_values was requested and the ID token has no acr");
            }
            if (!requested.contains(acr)) {
                throw new OidcError("validation", "the ID token acr " + acr + " is not one of the requested values (" + transaction.acrValues + ")");
            }
        }
        Login login = loginFrom(tokens, claims);
        login.sessionId = text(sessionId) ? sessionId : Codec.randomToken();
        sessions.put(login.sessionId, sessionTokens(login));
        return login;
    }

    /**
     * A valid access token for a session in the cache: the cached one while
     * it has more than 30 seconds left, otherwise one obtained with the
     * refresh token (with a DPoP proof when DPoP is in use), and the cache is
     * updated. A failed refresh removes the entry and is refused.
     *
     * @param sessionId the session identifier given to, or returned by,
     *        {@link #complete(Map, Transaction, String)}
     * @return the access token and its type
     */
    public Credentials sessionAccessToken(String sessionId) {
        if (!text(sessionId)) throw new OidcError("session", "there is no session identifier");
        Object lock = sessionLocks.computeIfAbsent(sessionId, id -> new Object());
        synchronized (lock) {
            SessionTokens cached = sessions.get(sessionId);
            if (cached == null) {
                sessionLocks.remove(sessionId, lock);
                throw new OidcError("session", "there are no tokens for this session");
            }
            long now = System.currentTimeMillis();
            if (cached.expiresAt() == 0 || cached.expiresAt() - now > SESSION_TOKEN_MARGIN_MS) return credentialsOf(cached);
            if (!text(cached.refreshToken())) {
                removeSession(sessionId);
                throw new OidcError("session", "the session's access token has expired and there is no refresh token");
            }
            Login previous = new Login();
            previous.subject = cached.subject();
            previous.idToken = cached.idToken();
            previous.claims = new LinkedHashMap<>(Map.of("sub", cached.subject()));
            Login refreshed;
            try {
                refreshed = refresh(cached.refreshToken(), previous);
            } catch (OidcError err) {
                Caught.error(err);
                removeSession(sessionId);
                throw new OidcError("session", "the session's refresh was refused: " + err.getMessage(), err, err.oauthError);
            }
            SessionTokens next = sessionTokens(refreshed);
            sessions.put(sessionId, next);
            return credentialsOf(next);
        }
    }

    /**
     * Removes a session's tokens from the cache: on sign-out, and when a CAEP
     * {@code session-revoked} event ends the session.
     *
     * @param sessionId the session identifier
     */
    public void removeSession(String sessionId) {
        if (!text(sessionId)) return;
        sessions.remove(sessionId);
        sessionLocks.remove(sessionId);
    }

    private static SessionTokens sessionTokens(Login login) {
        return new SessionTokens(login.subject, login.accessToken, login.tokenType, login.refreshToken, login.idToken,
                login.expiresAt == null ? 0 : login.expiresAt.getTime(), login.scope);
    }

    private static Credentials credentialsOf(SessionTokens tokens) {
        Credentials out = new Credentials();
        out.accessToken = tokens.accessToken();
        out.tokenType = tokens.tokenType();
        out.expiresAt = tokens.expiresAt() == 0 ? null : new Date(tokens.expiresAt());
        out.scope = tokens.scope();
        return out;
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
        CachedCredentials cached = clientCredentials;
        if (cached != null && cached.scope.equals(scope) && cached.until > now) {
            return cached.token;
        }
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("grant_type", "client_credentials");
        body.put("scope", scope);
        Credentials minted = credentialsFrom(token(body));
        long until = minted.expiresAt != null ? minted.expiresAt.getTime() - 30_000 : now + 60_000;
        clientCredentials = new CachedCredentials(scope, minted, until);
        return minted;
    }

    /**
     * Calls UserInfo with an access token this relying party obtained (a DPoP
     * token when DPoP is in use, otherwise a Bearer token).
     *
     * @param accessToken the access token
     * @param expectedSub the ID token's subject
     * @return the claims
     */
    public Map<String, Object> userinfo(String accessToken, String expectedSub) {
        return userinfo(accessToken, dpop != null ? "DPoP" : "Bearer", expectedSub);
    }

    /**
     * Calls UserInfo. A DPoP token is presented with a proof that carries
     * {@code ath}.
     *
     * @param accessToken the access token
     * @param tokenType the token's type, {@code DPoP} or {@code Bearer}
     * @param expectedSub the ID token's subject
     * @return the claims
     */
    public Map<String, Object> userinfo(String accessToken, String tokenType, String expectedSub) {
        if (!text(expectedSub)) throw new OidcError("validation", "userinfo needs the subject to check the response against");
        if (!text(metadata.get("userinfo_endpoint"))) throw new OidcError("discovery", "the provider has no userinfo_endpoint");
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("accept", "application/json, application/jwt");
        Http.Result answer = resource("GET", String.valueOf(metadata.get("userinfo_endpoint")), headers, null, accessToken, tokenType);
        if (answer.status() == 401) throw new OidcError("protocol", "userinfo refused the access token", null, "invalid_token");
        if (answer.status() != 200) throw new OidcError("protocol", "userinfo answered " + answer.status());
        Map<String, Object> claims;
        if (answer.contentType().contains("application/jwt")) {
            Map<String, Object> extra = new LinkedHashMap<>();
            extra.put("algorithms", algorithms);
            extra.put("requireTypAndAtHash", false);
            claims = idToken(answer.body().strip(), extra);
        } else {
            Object body;
            try {
                body = Jsons.read(answer.body());
            } catch (Exception err) {
                Caught.error(err);
                throw new OidcError("protocol", "userinfo did not answer JSON", err);
            }
            claims = Jsons.map(body);
            if (claims == null) throw new OidcError("validation", "userinfo did not answer a JSON object");
        }
        if (!expectedSub.equals(claims.get("sub"))) throw new OidcError("validation", "userinfo sub does not match the ID token sub");
        return claims;
    }

    /**
     * Sends one request to a resource server with an access token. A DPoP
     * token goes as {@code Authorization: DPoP} with a proof carrying
     * {@code ath}; a 401 whose {@code WWW-Authenticate} names
     * {@code use_dpop_nonce} is retried once with the nonce the response gave.
     *
     * @param method the HTTP method
     * @param url the URL
     * @param headers request headers, or null
     * @param body the body, or null
     * @param accessToken the access token
     * @param tokenType the token's type, {@code DPoP} or {@code Bearer}
     * @return the answer
     */
    public Http.Result resource(String method, String url, Map<String, String> headers, byte[] body, String accessToken, String tokenType) {
        boolean bound = "dpop".equalsIgnoreCase(tokenType);
        if (bound && dpop == null) throw new OidcError("protocol", "a DPoP token needs a DPoP key, and this relying party does not use DPoP");
        Http.Result answer = null;
        for (int attempt = 0; attempt < 2; attempt++) {
            Map<String, String> sent = new LinkedHashMap<>();
            if (headers != null) sent.putAll(headers);
            sent.keySet().removeIf(name -> "authorization".equalsIgnoreCase(name) || "dpop".equalsIgnoreCase(name));
            if (bound) {
                sent.put("authorization", "DPoP " + accessToken);
                sent.put("dpop", dpop.proof(method, url, accessToken));
            } else {
                sent.put("authorization", "Bearer " + accessToken);
            }
            answer = Http.send(url, method, sent, body, tls(), "protocol");
            if (!bound) return answer;
            String nonce = answer.header("dpop-nonce");
            dpop.rememberNonce(url, nonce);
            String challenge = answer.header("www-authenticate");
            boolean askedForNonce = answer.status() == 401 && challenge != null
                    && challenge.toLowerCase(java.util.Locale.ROOT).startsWith("dpop")
                    && challenge.contains("use_dpop_nonce");
            if (!askedForNonce || !text(nonce)) return answer;
        }
        return answer;
    }

    /**
     * A transport for the Shared Signals receiver: every call to the
     * transmitter presents a client credentials token for the scope, with a
     * DPoP proof when the token is DPoP-bound. A 401 that is not a nonce
     * challenge drops the cached client credentials token.
     *
     * @param scope the client credentials scope, usually {@code ssf.manage}
     * @return the transport
     */
    public SignalsReceiver.Transport transmitterTransport(String scope) {
        return (method, url, headers, body) -> {
            Credentials token = clientCredentials(scope);
            Http.Result answer = resource(method, url, headers, body, token.accessToken, token.tokenType);
            if (answer.status() == 401) clientCredentials = null;
            return answer;
        };
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
        checks.put("requireTypAndAtHash", config.get("requireIdTokenTypAndAtHash") != Boolean.FALSE);
        if (text(config.get("clientSecret"))) checks.put("clientSecret", config.get("clientSecret"));
        for (Map.Entry<String, Object> entry : extra.entrySet()) {
            if (!"algorithms".equals(entry.getKey())) checks.put(entry.getKey(), entry.getValue());
        }
        if (extra.get("requireTypAndAtHash") == Boolean.FALSE) checks.put("requireTypAndAtHash", false);
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
        if (dpop != null && !"dpop".equalsIgnoreCase(tokenType)) {
            throw new OidcError("protocol", "the token request carried a DPoP proof and the token_type is " + tokenType + ", not DPoP");
        }
        if (dpop == null && !"bearer".equalsIgnoreCase(tokenType)) {
            throw new OidcError("protocol", "the token request carried no DPoP proof and the token_type is " + tokenType + ", not Bearer");
        }
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
        Http.Result answer = null;
        for (int attempt = 0; attempt < 2; attempt++) {
            Map<String, String> headers = new LinkedHashMap<>();
            headers.put("accept", "application/json");
            headers.put("content-type", "application/x-www-form-urlencoded");
            Map<String, Object> fields = new LinkedHashMap<>(body);
            ClientAuth.apply(config, key, fields, headers, String.valueOf(metadata.get("issuer")));
            if (dpop != null) headers.put("dpop", dpop.proof("POST", url, null));
            answer = Http.send(url, "POST", headers, Codec.formBody(fields).getBytes(StandardCharsets.UTF_8), tls(), "protocol");
            if (dpop == null) break;
            String nonce = answer.header("dpop-nonce");
            dpop.rememberNonce(url, nonce);
            if (answer.status() != 400 || !text(nonce) || !answer.body().contains("use_dpop_nonce")) break;
            Map<String, Object> problem;
            try {
                problem = Jsons.map(Jsons.read(answer.body()));
            } catch (Exception err) {
                Caught.warn(err);
                problem = null;
            }
            if (problem == null || !"use_dpop_nonce".equals(problem.get("error"))) break;
        }
        Object parsed;
        try {
            parsed = answer.body() == null || answer.body().isEmpty() ? Map.of() : Jsons.read(answer.body());
        } catch (Exception err) {
            Caught.error(err);
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
        login.acr = claim(claims, "acr");
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
        /** The requested {@code acr_values} (space-separated), or null; the ID token's {@code acr} must be one of them. */
        public String acrValues;
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
        /** The ID token's {@code acr}, or null. */
        public String acr;
        /** The session cache handle this sign-in's tokens are kept under. */
        public String sessionId;
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
