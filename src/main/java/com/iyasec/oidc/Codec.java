// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.oidc;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Map;

/** Base64url, PKCE S256, and form encoding. */
public final class Codec {
    private static final SecureRandom RANDOM = new SecureRandom();

    private Codec() {}

    public static String b64UrlEncode(byte[] data) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(data);
    }

    public static byte[] b64UrlDecode(String value, String what) {
        if (value == null || !value.matches("^[A-Za-z0-9_-]*$")) {
            throw new IllegalArgumentException(what + " is not base64url");
        }
        int mod = value.length() % 4;
        String padded = mod == 0 ? value : value + "====".substring(mod);
        return Base64.getUrlDecoder().decode(padded);
    }

    public static String randomToken() {
        byte[] buf = new byte[32];
        RANDOM.nextBytes(buf);
        return b64UrlEncode(buf);
    }

    public static String codeChallengeS256(String verifier) {
        return b64UrlEncode(sha256(verifier.getBytes(StandardCharsets.UTF_8)));
    }

    public static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (Exception err) {
            Caught.error(err);
            throw new OidcError("protocol", err.getMessage(), err);
        }
    }

    public static String hex(byte[] data) {
        StringBuilder out = new StringBuilder(data.length * 2);
        for (byte b : data) {
            out.append(Character.forDigit((b >> 4) & 0xf, 16));
            out.append(Character.forDigit(b & 0xf, 16));
        }
        return out.toString();
    }

    /** application/x-www-form-urlencoded the way urllib.parse.urlencode encodes a body. */
    public static String formBody(Map<String, ?> fields) {
        StringBuilder out = new StringBuilder();
        for (Map.Entry<String, ?> entry : fields.entrySet()) {
            if (out.length() > 0) out.append('&');
            Object value = entry.getValue();
            out.append(quotePlus(entry.getKey())).append('=').append(quotePlus(value == null ? "" : String.valueOf(value)));
        }
        return out.toString();
    }

    /** RFC 6749 form-encoding of a Basic client id or secret. */
    public static String formEncode(String value) {
        StringBuilder out = new StringBuilder();
        for (byte b : String.valueOf(value).getBytes(StandardCharsets.UTF_8)) {
            int c = b & 0xff;
            if (unreserved(c) || c == '!' || c == '~' || c == '*' || c == '\'' || c == '(' || c == ')') out.append((char) c);
            else if (c == ' ') out.append('+');
            else percent(out, c);
        }
        return out.toString();
    }

    public static String quotePlus(String value) {
        StringBuilder out = new StringBuilder();
        for (byte b : value.getBytes(StandardCharsets.UTF_8)) {
            int c = b & 0xff;
            if (c == ' ') out.append('+');
            else if (unreserved(c) || c == '/') out.append((char) c);
            else percent(out, c);
        }
        return out.toString();
    }

    private static boolean unreserved(int c) {
        return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '.' || c == '-';
    }

    private static void percent(StringBuilder out, int c) {
        out.append('%');
        out.append(Character.toUpperCase(Character.forDigit(c >> 4, 16)));
        out.append(Character.toUpperCase(Character.forDigit(c & 0xf, 16)));
    }
}
