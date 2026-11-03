// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.oidc;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/** ID token checks: signature, issuer, audience, time, nonce, and at_hash / c_hash. */
public final class IdToken {
    private static final Set<String> NOT_ID_TOKEN = Set.of(
            "at+jwt", "application/at+jwt", "logout+jwt", "secevent+jwt", "dpop+jwt",
            "token-introspection+jwt", "software-statement+jwt", "jwt-bearer");

    private IdToken() {}

    public static String hashClaim(String value, String alg) {
        String name;
        if ("EdDSA".equals(alg) || "Ed25519".equals(alg)) name = "SHA-512";
        else if (alg != null && alg.contains("384")) name = "SHA-384";
        else if (alg != null && alg.contains("512")) name = "SHA-512";
        else name = "SHA-256";
        try {
            byte[] digest = MessageDigest.getInstance(name).digest(value.getBytes(StandardCharsets.UTF_8));
            return Codec.b64UrlEncode(Arrays.copyOf(digest, digest.length / 2));
        } catch (Exception err) {
            Caught.error(err);
            throw new OidcError("validation", err.getMessage(), err);
        }
    }

    public static Map<String, Object> validate(String token, Map<String, Object> checks) {
        Map<String, Object> header = part(token, 0);
        String alg = header.get("alg") == null ? "" : String.valueOf(header.get("alg"));
        List<String> algorithms = strings(checks.get("algorithms"));
        if (!algorithms.contains(alg)) {
            throw new OidcError("signature", "the ID token is signed with " + (alg.isEmpty() ? "(no alg)" : alg) + ", which this client does not accept");
        }
        if (header.containsKey("crit") && header.get("crit") != null) {
            throw new OidcError("validation", "the ID token has a crit header this client does not understand");
        }
        boolean strict = checks.get("requireTypAndAtHash") != Boolean.FALSE;
        String typ = header.get("typ") == null ? "" : String.valueOf(header.get("typ")).toLowerCase(Locale.ROOT);
        if (strict && typ.isEmpty()) {
            throw new OidcError("validation", "the ID token header has no typ (JWT is required)");
        }
        if (!typ.isEmpty() && ((!typ.equals("jwt") && !typ.equals("application/jwt")) || NOT_ID_TOKEN.contains(typ))) {
            throw new OidcError("validation", "the ID token typ is " + header.get("typ") + ", not an ID token");
        }
        if (alg.startsWith("HS") && (checks.get("clientSecret") == null || String.valueOf(checks.get("clientSecret")).isEmpty())) {
            throw new OidcError("config", alg + " ID tokens need the client secret");
        }
        Map<String, Object> payload = part(token, 1);
        boolean ok;
        try {
            ok = signatureOk(token, alg, maps(checks.get("jwks")), checks.get("clientSecret") == null ? "" : String.valueOf(checks.get("clientSecret")));
        } catch (OidcError err) {
            throw err;
        } catch (Exception err) {
            Caught.error(err);
            throw new OidcError("signature", "the ID token was refused: signature: " + err, err);
        }
        if (!ok) throw new OidcError("signature", "the ID token was refused: signature verification failed");
        if (!String.valueOf(checks.get("issuer")).equals(String.valueOf(payload.get("iss")))) {
            throw new OidcError("validation", "the ID token was refused: issuer mismatch");
        }
        List<String> audiences = audiences(payload.get("aud"));
        if (!audiences.contains(String.valueOf(checks.get("clientId")))) {
            throw new OidcError("validation", "the ID token audience does not include this client");
        }
        double now = System.currentTimeMillis() / 1000.0;
        double tolerance = checks.get("clockToleranceSec") instanceof Number number ? number.doubleValue() : 0;
        if (!(payload.get("exp") instanceof Number exp)) throw new OidcError("validation", "the ID token was refused: exp is missing");
        if (exp.doubleValue() + tolerance < now) throw new OidcError("validation", "the ID token was refused: exp expired");
        if (payload.get("iat") instanceof Number iat && iat.doubleValue() - tolerance > now) {
            throw new OidcError("validation", "the ID token was refused: iat is in the future");
        }
        if (payload.get("nbf") instanceof Number nbf && nbf.doubleValue() - tolerance > now) {
            throw new OidcError("validation", "the ID token was refused: nbf is in the future");
        }
        if (checks.get("maxIdTokenAgeSec") != null) {
            if (!(payload.get("iat") instanceof Number)) throw new OidcError("validation", "the ID token was refused: iat is missing");
            double maxAge = ((Number) checks.get("maxIdTokenAgeSec")).doubleValue();
            if ((now - ((Number) payload.get("iat")).doubleValue()) - tolerance > maxAge) {
                throw new OidcError("validation", "the ID token was refused: iat is too old");
            }
        }
        if (!(payload.get("sub") instanceof String sub) || sub.isEmpty()) throw new OidcError("validation", "the ID token has no sub");
        if (audiences.size() > 1 && !String.valueOf(checks.get("clientId")).equals(payload.get("azp"))) {
            throw new OidcError("validation", "an ID token with several audiences must name this client as azp");
        }
        if (payload.containsKey("azp") && payload.get("azp") != null && !String.valueOf(checks.get("clientId")).equals(payload.get("azp"))) {
            throw new OidcError("validation", "the ID token azp is " + payload.get("azp") + ", not " + checks.get("clientId"));
        }
        if (checks.get("nonce") != null) {
            if (!(payload.get("nonce") instanceof String nonce) || !same(nonce, String.valueOf(checks.get("nonce")))) {
                throw new OidcError("validation", "the ID token nonce does not match this sign-in");
            }
        }
        if (checks.get("previousSub") != null && !String.valueOf(checks.get("previousSub")).equals(payload.get("sub"))) {
            throw new OidcError("validation", "the refreshed ID token is for a different subject");
        }
        if (truthy(checks.get("accessToken"))) {
            if (strict && payload.get("at_hash") == null) {
                throw new OidcError("validation", "the token response carries an access token and the ID token has no at_hash");
            }
            checkHash(payload.get("at_hash"), String.valueOf(checks.get("accessToken")), alg, "at_hash");
        }
        if (truthy(checks.get("code"))) checkHash(payload.get("c_hash"), String.valueOf(checks.get("code")), alg, "c_hash");
        if (checks.get("maxAge") != null) {
            if (!(payload.get("auth_time") instanceof Number authTime)) {
                throw new OidcError("validation", "max_age was requested and the ID token has no auth_time");
            }
            long maxAge = ((Number) checks.get("maxAge")).longValue();
            if (authTime.doubleValue() < (System.currentTimeMillis() / 1000) - maxAge - tolerance) {
                throw new OidcError("validation", "the ID token auth_time is older than max_age");
            }
        }
        return payload;
    }

    public static List<Map<String, Object>> fetchJwks(String jwksUri, Map<String, String> tls) {
        Http.Result answer = Http.send(jwksUri, "GET", Map.of("accept", "application/json"), null, tls, "discovery");
        if (answer.status() != 200) throw new OidcError("discovery", "the JWKS at " + jwksUri + " answered " + answer.status());
        Object body;
        try {
            body = Jsons.read(answer.body());
        } catch (Exception err) {
            Caught.error(err);
            throw new OidcError("discovery", "the JWKS at " + jwksUri + " is not JSON", err);
        }
        Map<String, Object> doc = Jsons.map(body);
        List<Object> keys = doc == null ? null : Jsons.list(doc.get("keys"));
        if (doc == null || keys == null) throw new OidcError("discovery", "the JWKS at " + jwksUri + " has no keys");
        List<Map<String, Object>> out = new ArrayList<>();
        for (Object key : keys) {
            Map<String, Object> jwk = Jsons.map(key);
            if (jwk != null) out.add(jwk);
        }
        return out;
    }

    private static void checkHash(Object claim, String value, String alg, String name) {
        if (claim == null) return;
        if (!(claim instanceof String text) || !same(text, hashClaim(value, alg))) {
            throw new OidcError("validation", "the ID token's " + name + " does not match");
        }
    }

    private static boolean signatureOk(String token, String alg, List<Map<String, Object>> jwks, String secret) {
        String[] parts = token.split("\\.", -1);
        byte[] input = (parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII);
        byte[] signature;
        try {
            signature = Codec.b64UrlDecode(parts[2], "signature");
        } catch (Exception err) {
            Caught.error(err);
            throw new OidcError("signature", "the ID token is not a compact JWS: " + err, err);
        }
        if (alg.startsWith("HS")) return JwsCrypto.verifyHmac(secret.getBytes(StandardCharsets.UTF_8), alg, input, signature);
        Map<String, Object> header = part(token, 0);
        String kid = header.get("kid") instanceof String text ? text : null;
        List<Map<String, Object>> keys = candidates(jwks, alg, kid);
        if (keys.isEmpty()) throw new OidcError("signature", "signature verification failed: no applicable key");
        for (Map<String, Object> jwk : keys) {
            PublicKey key;
            try {
                key = JwsCrypto.publicKey(jwk);
            } catch (OidcError err) {
                continue;
            }
            if (JwsCrypto.verify(key, alg, input, signature)) return true;
        }
        return false;
    }

    private static List<Map<String, Object>> candidates(List<Map<String, Object>> jwks, String alg, String kid) {
        String[] spec = JwsCrypto.alg(alg);
        List<Map<String, Object>> found = new ArrayList<>();
        if (spec == null || jwks == null) return found;
        for (Map<String, Object> jwk : jwks) {
            if (kid != null && !kid.equals(jwk.get("kid"))) continue;
            if (!spec[0].equals(jwk.get("kty"))) continue;
            if (jwk.get("use") != null && !"sig".equals(jwk.get("use"))) continue;
            if (jwk.get("alg") != null && !alg.equals(jwk.get("alg"))) continue;
            found.add(jwk);
        }
        return found;
    }

    private static Map<String, Object> part(String token, int index) {
        String[] parts = token == null ? new String[0] : token.split("\\.", -1);
        if (parts.length != 3 || parts[0].isEmpty() || parts[1].isEmpty() || parts[2].isEmpty()) {
            throw new OidcError("signature", "the ID token is not a compact JWS: not a compact JWS");
        }
        try {
            Object parsed = Jsons.read(new String(Codec.b64UrlDecode(parts[index], index == 0 ? "header" : "payload"), StandardCharsets.UTF_8));
            Map<String, Object> object = Jsons.map(parsed);
            if (object == null) throw new OidcError("signature", "the ID token is not a compact JWS: not a JSON object");
            return object;
        } catch (OidcError err) {
            throw err;
        } catch (Exception err) {
            Caught.error(err);
            throw new OidcError("signature", "the ID token is not a compact JWS: " + err, err);
        }
    }

    private static List<String> audiences(Object aud) {
        if (aud instanceof List<?> items) {
            List<String> out = new ArrayList<>();
            for (Object item : items) out.add(String.valueOf(item));
            return out;
        }
        return List.of(aud == null ? "" : String.valueOf(aud));
    }

    private static List<String> strings(Object value) {
        List<String> out = new ArrayList<>();
        if (value instanceof List<?> items) for (Object item : items) out.add(String.valueOf(item));
        return out;
    }

    private static List<Map<String, Object>> maps(Object value) {
        List<Map<String, Object>> out = new ArrayList<>();
        if (value instanceof List<?> items) for (Object item : items) {
            Map<String, Object> map = Jsons.map(item);
            if (map != null) out.add(map);
        }
        return out;
    }

    private static boolean same(String left, String right) {
        return MessageDigest.isEqual(left.getBytes(StandardCharsets.UTF_8), right.getBytes(StandardCharsets.UTF_8));
    }

    private static boolean truthy(Object value) {
        if (value == null || value == Boolean.FALSE) return false;
        if (value instanceof String text) return !text.isEmpty();
        return true;
    }
}
