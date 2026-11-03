// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.oidc;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECFieldFp;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * DPoP (RFC 9449): one ES256 (P-256) key pair and the proofs it signs.
 *
 * <p>The key is generated when the relying party is created and is held in
 * memory only, unless the configuration names a PEM private key
 * ({@code dpopKey}). The latest {@code DPoP-Nonce} each server gave is
 * remembered per origin and sent on the next proof to that origin.
 */
public final class Dpop {
    /** The one proof algorithm this library signs with. */
    public static final String ALG = "ES256";

    private static final BigInteger P256_ORDER = new BigInteger(
            "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16);
    private static final byte[] P256_ALGORITHM = hexBytes(
            "301306072a8648ce3d020106082a8648ce3d030107");

    private final PrivateKey key;
    private final Map<String, Object> jwk;
    private final String thumbprint;
    private final Map<String, String> nonces = new ConcurrentHashMap<>();

    private Dpop(PrivateKey key, ECPublicKey publicKey) {
        this.key = key;
        int size = 32;
        Map<String, Object> out = new LinkedHashMap<>();
        // RFC 7638: the required members in lexicographic order.
        out.put("crv", "P-256");
        out.put("kty", "EC");
        out.put("x", Codec.b64UrlEncode(fixed(publicKey.getW().getAffineX(), size)));
        out.put("y", Codec.b64UrlEncode(fixed(publicKey.getW().getAffineY(), size)));
        this.jwk = java.util.Collections.unmodifiableMap(out);
        this.thumbprint = Codec.b64UrlEncode(Codec.sha256(Jsons.write(out).getBytes(StandardCharsets.UTF_8)));
    }

    /**
     * A new key pair, held in memory only.
     *
     * @return a DPoP signer with a fresh P-256 key
     */
    public static Dpop generate() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
            generator.initialize(new ECGenParameterSpec("secp256r1"));
            KeyPair pair = generator.generateKeyPair();
            return new Dpop(pair.getPrivate(), (ECPublicKey) pair.getPublic());
        } catch (Exception err) {
            Caught.error(err);
            throw new OidcError("config", "a DPoP key could not be generated: " + err, err);
        }
    }

    /**
     * A signer for a P-256 private key in PEM: PKCS#8 ({@code BEGIN PRIVATE
     * KEY}) or SEC 1 ({@code BEGIN EC PRIVATE KEY}).
     *
     * @param pem the private key
     * @return a DPoP signer with that key
     */
    public static Dpop fromPem(String pem) {
        if (pem == null || !pem.contains("-----BEGIN")) throw new OidcError("config", "dpopKey is not a PEM private key");
        boolean sec1 = pem.contains("-----BEGIN EC PRIVATE KEY-----");
        ECPrivateKey key;
        try {
            StringBuilder body = new StringBuilder();
            for (String line : pem.split("\\r?\\n")) {
                String trimmed = line.strip();
                if (trimmed.isEmpty() || trimmed.startsWith("-----") || trimmed.contains(":")) continue;
                body.append(trimmed);
            }
            byte[] der = Base64.getDecoder().decode(body.toString());
            if (sec1) der = pkcs8(der);
            PrivateKey parsed = KeyFactory.getInstance("EC").generatePrivate(new java.security.spec.PKCS8EncodedKeySpec(der));
            key = (ECPrivateKey) parsed;
        } catch (Exception err) {
            Caught.error(err);
            throw new OidcError("config", "dpopKey could not be read as a P-256 private key: " + err, err);
        }
        if (!P256_ORDER.equals(key.getParams().getOrder())) {
            throw new OidcError("config", "dpopKey must be a P-256 key (ES256)");
        }
        ECPublicKey publicKey = publicOf(key);
        return new Dpop(key, publicKey);
    }

    /**
     * The JWK SHA-256 thumbprint (RFC 7638) of the public key: the value of
     * {@code dpop_jkt}.
     *
     * @return the base64url thumbprint
     */
    public String thumbprint() {
        return thumbprint;
    }

    /**
     * The public key as a JWK, as it goes in each proof's header.
     *
     * @return the public JWK
     */
    public Map<String, Object> jwk() {
        return jwk;
    }

    /**
     * A proof for one request. The nonce last remembered for the URL's origin
     * is included.
     *
     * @param method the HTTP method
     * @param url the request URL; its query and fragment are left out of {@code htu}
     * @param accessToken the access token the request presents, or null on a
     *        request to the authorization server; when given, the proof carries
     *        {@code ath}
     * @return the compact JWS for the {@code DPoP} header
     */
    public String proof(String method, String url, String accessToken) {
        Map<String, Object> header = new LinkedHashMap<>();
        header.put("typ", "dpop+jwt");
        header.put("alg", ALG);
        header.put("jwk", jwk);
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("jti", UUID.randomUUID().toString());
        payload.put("htm", method.toUpperCase(Locale.ROOT));
        payload.put("htu", htu(url));
        payload.put("iat", System.currentTimeMillis() / 1000);
        String nonce = nonce(url);
        if (nonce != null) payload.put("nonce", nonce);
        if (accessToken != null && !accessToken.isEmpty()) {
            payload.put("ath", Codec.b64UrlEncode(Codec.sha256(accessToken.getBytes(StandardCharsets.US_ASCII))));
        }
        return JwsCrypto.signCompact(header, payload, key, ALG);
    }

    /**
     * Remember the latest nonce a server gave.
     *
     * @param url any URL on that server
     * @param nonce the {@code DPoP-Nonce} value; null or empty is ignored
     */
    public void rememberNonce(String url, String nonce) {
        if (nonce == null || nonce.isEmpty()) return;
        String origin = origin(url);
        if (origin != null) nonces.put(origin, nonce);
    }

    /**
     * The nonce remembered for a server.
     *
     * @param url any URL on that server
     * @return the nonce, or null
     */
    public String nonce(String url) {
        String origin = origin(url);
        return origin == null ? null : nonces.get(origin);
    }

    /**
     * The {@code htu} of a URL: scheme, authority and path, with no query or
     * fragment.
     *
     * @param url the request URL
     * @return the htu value
     */
    public static String htu(String url) {
        URI uri = URI.create(url);
        String path = uri.getRawPath() == null || uri.getRawPath().isEmpty() ? "/" : uri.getRawPath();
        return uri.getScheme().toLowerCase(Locale.ROOT) + "://" + uri.getRawAuthority().toLowerCase(Locale.ROOT) + path;
    }

    static String origin(String url) {
        try {
            URI uri = URI.create(url);
            if (uri.getScheme() == null || uri.getRawAuthority() == null) return null;
            return uri.getScheme().toLowerCase(Locale.ROOT) + "://" + uri.getRawAuthority().toLowerCase(Locale.ROOT);
        } catch (IllegalArgumentException err) {
            Caught.warn(err);
            return null;
        }
    }

    private static ECPublicKey publicOf(ECPrivateKey key) {
        ECParameterSpec params = key.getParams();
        BigInteger p = ((ECFieldFp) params.getCurve().getField()).getP();
        BigInteger a = params.getCurve().getA();
        ECPoint w = multiply(params.getGenerator(), key.getS(), p, a);
        try {
            PublicKey publicKey = KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(w, params));
            return (ECPublicKey) publicKey;
        } catch (Exception err) {
            Caught.error(err);
            throw new OidcError("config", "dpopKey's public key could not be derived: " + err, err);
        }
    }

    private static ECPoint multiply(ECPoint g, BigInteger k, BigInteger p, BigInteger a) {
        ECPoint result = ECPoint.POINT_INFINITY;
        for (int i = k.bitLength() - 1; i >= 0; i--) {
            result = add(result, result, p, a);
            if (k.testBit(i)) result = add(result, g, p, a);
        }
        return result;
    }

    private static ECPoint add(ECPoint left, ECPoint right, BigInteger p, BigInteger a) {
        if (ECPoint.POINT_INFINITY.equals(left)) return right;
        if (ECPoint.POINT_INFINITY.equals(right)) return left;
        BigInteger x1 = left.getAffineX();
        BigInteger y1 = left.getAffineY();
        BigInteger x2 = right.getAffineX();
        BigInteger y2 = right.getAffineY();
        BigInteger lambda;
        if (x1.equals(x2)) {
            if (y1.add(y2).mod(p).signum() == 0) return ECPoint.POINT_INFINITY;
            lambda = x1.pow(2).multiply(BigInteger.valueOf(3)).add(a)
                    .multiply(y1.shiftLeft(1).modInverse(p)).mod(p);
        } else {
            lambda = y2.subtract(y1).multiply(x2.subtract(x1).modInverse(p)).mod(p);
        }
        BigInteger x3 = lambda.pow(2).subtract(x1).subtract(x2).mod(p);
        BigInteger y3 = lambda.multiply(x1.subtract(x3)).subtract(y1).mod(p);
        return new ECPoint(x3, y3);
    }

    /** Wraps a SEC 1 ECPrivateKey (P-256) in PKCS#8. */
    private static byte[] pkcs8(byte[] sec1) {
        ByteArrayOutputStream inner = new ByteArrayOutputStream();
        inner.writeBytes(new byte[] {0x02, 0x01, 0x00});
        inner.writeBytes(P256_ALGORITHM);
        inner.write(0x04);
        inner.writeBytes(derLength(sec1.length));
        inner.writeBytes(sec1);
        byte[] content = inner.toByteArray();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(0x30);
        out.writeBytes(derLength(content.length));
        out.writeBytes(content);
        return out.toByteArray();
    }

    private static byte[] derLength(int length) {
        if (length < 0x80) return new byte[] {(byte) length};
        if (length < 0x100) return new byte[] {(byte) 0x81, (byte) length};
        return new byte[] {(byte) 0x82, (byte) (length >> 8), (byte) length};
    }

    private static byte[] fixed(BigInteger value, int size) {
        byte[] raw = value.toByteArray();
        byte[] out = new byte[size];
        int copy = Math.min(raw.length, size);
        System.arraycopy(raw, raw.length - copy, out, size - copy, copy);
        return out;
    }

    private static byte[] hexBytes(String hex) {
        byte[] out = new byte[hex.length() / 2];
        for (int i = 0; i < out.length; i++) out[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        return out;
    }
}
