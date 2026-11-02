// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.oidc.ssf;

import com.iyasec.oidc.Caught;
import com.iyasec.oidc.Codec;
import com.iyasec.oidc.Jsons;
import com.iyasec.oidc.JwsCrypto;
import com.iyasec.oidc.OidcError;

import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Verify a Security Event Token. The key comes from the JWKS, never from the token. */
public final class SecEvent {
    private SecEvent() {}

    public static Map<String, Object> verifyCompactJws(String token, List<Map<String, Object>> keys) {
        String[] parts = token == null ? new String[0] : token.split("\\.", -1);
        if (parts.length != 3 || parts[0].isEmpty() || parts[1].isEmpty() || parts[2].isEmpty()) {
            throw new OidcError("signature", "the SET is not a compact JWS");
        }
        Map<String, Object> header;
        Map<String, Object> payload;
        try {
            header = object(parts[0], "header");
            payload = object(parts[1], "payload");
        } catch (OidcError err) {
            throw err;
        } catch (IllegalArgumentException err) {
            Caught.error(err);
            String message = String.valueOf(err.getMessage());
            if (message.contains("base64url")) {
                String what = message.contains("header") ? "header" : message.contains("payload") ? "payload" : "signature";
                throw new OidcError("signature", "the SET's " + what + " is not base64url", err);
            }
            throw new OidcError("signature", "the SET's header or payload is not JSON", err);
        }
        if (header == null || payload == null) throw new OidcError("signature", "the SET's header or payload is not a JSON object");
        String alg = header.get("alg") == null ? "" : String.valueOf(header.get("alg"));
        String[] spec = JwsCrypto.alg(alg);
        if (spec == null || "hmac".equals(spec[2])) {
            throw new OidcError("signature", "the SET is signed with " + (alg.isEmpty() ? "(no alg)" : alg)
                    + ", which this receiver does not verify (" + String.join(", ", JwsCrypto.SUPPORTED) + ")");
        }
        if (header.containsKey("crit") && header.get("crit") != null) {
            throw new OidcError("signature", "the SET's header has a crit member this receiver does not understand");
        }
        String kid = header.get("kid") instanceof String text ? text : null;
        List<Map<String, Object>> candidates = new ArrayList<>();
        for (Map<String, Object> jwk : keys) {
            boolean kidOk = kid == null || kid.equals(jwk.get("kid"));
            boolean useOk = jwk.get("use") == null || "sig".equals(jwk.get("use"));
            boolean algOk = jwk.get("alg") == null || alg.equals(jwk.get("alg"));
            if (kidOk && spec[0].equals(jwk.get("kty")) && useOk && algOk) candidates.add(jwk);
        }
        if (candidates.isEmpty()) {
            String suffix = kid == null ? "" : " with kid " + kid;
            throw new OidcError("signature", "the transmitter publishes no " + spec[0] + " signing key" + suffix);
        }
        byte[] signature;
        try {
            signature = Codec.b64UrlDecode(parts[2], "signature");
        } catch (Exception err) {
            Caught.error(err);
            throw new OidcError("signature", "the SET's signature is not base64url", err);
        }
        byte[] data = (parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII);
        for (Map<String, Object> jwk : candidates) {
            PublicKey key = JwsCrypto.publicKey(jwk);
            if (JwsCrypto.verify(key, alg, data, signature)) {
                Map<String, Object> out = new LinkedHashMap<>();
                out.put("header", header);
                out.put("payload", payload);
                return out;
            }
        }
        throw new OidcError("signature", "the SET's signature does not verify against the transmitter's keys");
    }

    private static Map<String, Object> object(String part, String what) {
        Object parsed = Jsons.read(new String(Codec.b64UrlDecode(part, what), StandardCharsets.UTF_8));
        return Jsons.map(parsed);
    }
}
