// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.oidc;

import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

/** Client authentication on a token or pushed-authorization request. */
public final class ClientAuth {
    private ClientAuth() {}

    public static void apply(Map<String, Object> config, PrivateKey key, Map<String, Object> body, Map<String, String> headers, String audience) {
        String method = String.valueOf(config.get("tokenEndpointAuthMethod"));
        String clientId = String.valueOf(config.get("clientId"));
        if ("client_secret_basic".equals(method)) {
            String secret = config.get("clientSecret") == null ? "" : String.valueOf(config.get("clientSecret"));
            String raw = Codec.formEncode(clientId) + ":" + Codec.formEncode(secret);
            headers.put("authorization", "Basic " + Base64.getEncoder().encodeToString(raw.getBytes(StandardCharsets.UTF_8)));
            return;
        }
        if ("client_secret_post".equals(method)) {
            body.put("client_id", clientId);
            body.put("client_secret", config.get("clientSecret") == null ? "" : String.valueOf(config.get("clientSecret")));
            return;
        }
        if (key == null) throw new OidcError("config", "private_key_jwt has no signing key");
        long now = System.currentTimeMillis() / 1000;
        String alg = config.get("privateKeyAlg") == null || String.valueOf(config.get("privateKeyAlg")).isEmpty()
                ? "RS256" : String.valueOf(config.get("privateKeyAlg"));
        Map<String, Object> header = new LinkedHashMap<>();
        header.put("alg", alg);
        header.put("typ", "JWT");
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("iss", clientId);
        payload.put("sub", clientId);
        payload.put("aud", audience);
        payload.put("jti", UUID.randomUUID().toString());
        payload.put("iat", now);
        payload.put("exp", now + 60);
        body.put("client_id", clientId);
        body.put("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
        body.put("client_assertion", JwsCrypto.signCompact(header, payload, key, alg));
    }
}
