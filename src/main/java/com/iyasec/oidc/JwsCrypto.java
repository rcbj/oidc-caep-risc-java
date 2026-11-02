// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.oidc;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.EdECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.PSSParameterSpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** JWS sign and verify. HMAC is used only when an ID token names it. */
public final class JwsCrypto {
    public static final List<String> SUPPORTED = List.of(
            "RS256", "RS384", "RS512", "PS256", "PS384", "PS512",
            "ES256", "ES384", "ES512", "EdDSA", "Ed25519");

    private static final Map<String, String[]> ALGS = new LinkedHashMap<>();
    private static final byte[] ED25519_X509_PREFIX = new byte[] {
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00
    };

    static {
        put("RS256", "RSA", "SHA-256", "pkcs1");
        put("RS384", "RSA", "SHA-384", "pkcs1");
        put("RS512", "RSA", "SHA-512", "pkcs1");
        put("PS256", "RSA", "SHA-256", "pss");
        put("PS384", "RSA", "SHA-384", "pss");
        put("PS512", "RSA", "SHA-512", "pss");
        put("ES256", "EC", "SHA-256", "p1363");
        put("ES384", "EC", "SHA-384", "p1363");
        put("ES512", "EC", "SHA-512", "p1363");
        put("EdDSA", "OKP", "", "eddsa");
        put("Ed25519", "OKP", "", "eddsa");
        put("HS256", "oct", "SHA-256", "hmac");
        put("HS384", "oct", "SHA-384", "hmac");
        put("HS512", "oct", "SHA-512", "hmac");
    }

    private JwsCrypto() {}

    private static void put(String alg, String kty, String hash, String mode) {
        ALGS.put(alg, new String[] {kty, hash, mode});
    }

    public static String[] alg(String name) {
        return ALGS.get(name);
    }

    public static PublicKey publicKey(Map<String, Object> jwk) {
        try {
            String kty = string(jwk.get("kty"));
            if ("RSA".equals(kty)) {
                RSAPublicKeySpec spec = new RSAPublicKeySpec(uint(string(jwk.get("n"))), uint(string(jwk.get("e"))));
                return KeyFactory.getInstance("RSA").generatePublic(spec);
            }
            if ("EC".equals(kty)) {
                String curve = string(jwk.get("crv"));
                String name = switch (curve == null ? "" : curve) {
                    case "P-256" -> "secp256r1";
                    case "P-384" -> "secp384r1";
                    case "P-521" -> "secp521r1";
                    default -> throw new IllegalArgumentException(curve);
                };
                int size = "P-521".equals(curve) ? 66 : "P-384".equals(curve) ? 48 : 32;
                byte[] x = Codec.b64UrlDecode(string(jwk.get("x")), "x");
                byte[] y = Codec.b64UrlDecode(string(jwk.get("y")), "y");
                if (x.length != size || y.length != size) throw new IllegalArgumentException("EC coordinate length");
                java.security.AlgorithmParameters parameters = java.security.AlgorithmParameters.getInstance("EC");
                parameters.init(new java.security.spec.ECGenParameterSpec(name));
                ECParameterSpec ec = parameters.getParameterSpec(ECParameterSpec.class);
                ECPublicKeySpec spec = new ECPublicKeySpec(new ECPoint(new BigInteger(1, x), new BigInteger(1, y)), ec);
                return KeyFactory.getInstance("EC").generatePublic(spec);
            }
            if ("OKP".equals(kty)) {
                if (jwk.get("crv") != null && !"Ed25519".equals(string(jwk.get("crv")))) {
                    throw new IllegalArgumentException(string(jwk.get("crv")));
                }
                byte[] raw = Codec.b64UrlDecode(string(jwk.get("x")), "x");
                byte[] encoded = Arrays.copyOf(ED25519_X509_PREFIX, ED25519_X509_PREFIX.length + raw.length);
                System.arraycopy(raw, 0, encoded, ED25519_X509_PREFIX.length, raw.length);
                return KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(encoded));
            }
        } catch (OidcError err) {
            throw err;
        } catch (Exception err) {
            throw new OidcError("signature", "the transmitter's key " + (jwk.get("kid") == null ? "" : jwk.get("kid")) + " cannot be read: " + err, err);
        }
        throw new OidcError("signature", "the key type " + jwk.get("kty") + " cannot be read");
    }

    public static PrivateKey loadPrivateKey(String pem, String alg) {
        String[] spec = ALGS.get(alg);
        PrivateKey key;
        try {
            String body = pem.replace("-----BEGIN PRIVATE KEY-----", "").replace("-----END PRIVATE KEY-----", "").replaceAll("\\s", "");
            key = readPkcs8(Base64.getDecoder().decode(body));
        } catch (Exception err) {
            throw new OidcError("config", "the private key could not be read as " + alg + ": " + err, err);
        }
        if (spec == null) throw new OidcError("config", "the private key could not be read as " + alg + ": unsupported algorithm");
        boolean ok = false;
        if ("RSA".equals(spec[0]) && key instanceof RSAPrivateKey) ok = true;
        else if ("EC".equals(spec[0]) && key instanceof ECPrivateKey ec) ok = alg.equals(ecAlg(ec));
        else if ("OKP".equals(spec[0]) && key instanceof EdECPrivateKey) ok = true;
        if (!ok) throw new OidcError("config", "the private key could not be read as " + alg + ": key type does not match " + alg);
        return key;
    }

    public static String signCompact(Map<String, Object> header, Map<String, Object> payload, PrivateKey key, String alg) {
        try {
            String signingInput = Codec.b64UrlEncode(Jsons.write(header).getBytes(java.nio.charset.StandardCharsets.UTF_8))
                    + "." + Codec.b64UrlEncode(Jsons.write(payload).getBytes(java.nio.charset.StandardCharsets.UTF_8));
            byte[] signature = sign(key, alg, signingInput.getBytes(java.nio.charset.StandardCharsets.US_ASCII));
            return signingInput + "." + Codec.b64UrlEncode(signature);
        } catch (OidcError err) {
            throw err;
        } catch (Exception err) {
            throw new OidcError("protocol", "the client assertion could not be signed: " + err, err);
        }
    }

    public static byte[] sign(PrivateKey key, String alg, byte[] input) {
        String[] spec = ALGS.get(alg);
        try {
            if ("hmac".equals(spec[2])) return mac(spec[1], key.getEncoded(), input);
            if ("RSA".equals(spec[0]) || "EC".equals(spec[0])) {
                Signature signature = signature(spec, key instanceof ECPrivateKey ec ? ecSize(ec) : 0);
                signature.initSign(key);
                signature.update(input);
                byte[] raw = signature.sign();
                if ("EC".equals(spec[0])) return derToP1363(raw, ecSize((ECPrivateKey) key));
                return raw;
            }
            Signature signature = Signature.getInstance("Ed25519");
            signature.initSign(key);
            signature.update(input);
            return signature.sign();
        } catch (OidcError err) {
            throw err;
        } catch (Exception err) {
            throw new OidcError("protocol", "the client assertion could not be signed: " + err, err);
        }
    }

    public static boolean verify(PublicKey key, String alg, byte[] input, byte[] signature) {
        return verifyAny(key, alg, input, signature);
    }

    public static boolean verifyHmac(byte[] secret, String alg, byte[] input, byte[] signature) {
        String[] spec = ALGS.get(alg);
        if (spec == null || !"hmac".equals(spec[2]) || secret == null) return false;
        try {
            return MessageDigest.isEqual(mac(spec[1], secret, input), signature);
        } catch (Exception err) {
            return false;
        }
    }

    private static boolean verifyAny(Object key, String alg, byte[] input, byte[] signature) {
        String[] spec = ALGS.get(alg);
        if (spec == null || key == null || "hmac".equals(spec[2])) return false;
        try {
            if ("RSA".equals(spec[0])) {
                Signature verifier = signature(spec, 0);
                verifier.initVerify((PublicKey) key);
                verifier.update(input);
                return verifier.verify(signature);
            }
            if ("EC".equals(spec[0])) {
                int size = ecSize((ECPublicKey) key);
                if (signature.length != size * 2) return false;
                byte[] der = p1363ToDer(signature, size);
                Signature verifier = signature(spec, size);
                verifier.initVerify((PublicKey) key);
                verifier.update(input);
                return verifier.verify(der);
            }
            Signature verifier = Signature.getInstance("Ed25519");
            verifier.initVerify((PublicKey) key);
            verifier.update(input);
            return verifier.verify(signature);
        } catch (GeneralSecurityException | IllegalArgumentException err) {
            return false;
        } catch (Exception err) {
            return false;
        }
    }

    private static Signature signature(String[] spec, int ecSize) throws GeneralSecurityException {
        if ("pss".equals(spec[2])) {
            Signature signature = Signature.getInstance("RSASSA-PSS");
            int salt = MessageDigest.getInstance(spec[1]).getDigestLength();
            signature.setParameter(new PSSParameterSpec(spec[1], "MGF1", new MGF1ParameterSpec(spec[1]), salt, 1));
            return signature;
        }
        if ("EC".equals(spec[0])) return Signature.getInstance(spec[1].replace("-", "") + "withECDSA");
        return Signature.getInstance(spec[1].replace("-", "") + "withRSA");
    }

    private static byte[] mac(String hash, byte[] secret, byte[] input) throws GeneralSecurityException {
        Mac mac = Mac.getInstance("Hmac" + hash.replace("-", ""));
        mac.init(new SecretKeySpec(secret, mac.getAlgorithm()));
        mac.update(input);
        return mac.doFinal();
    }

    private static PrivateKey readPkcs8(byte[] der) throws GeneralSecurityException {
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(der);
        GeneralSecurityException last = null;
        for (String algorithm : new String[] {"RSA", "EC", "Ed25519"}) {
            try {
                return KeyFactory.getInstance(algorithm).generatePrivate(spec);
            } catch (GeneralSecurityException err) {
                last = err;
            }
        }
        throw last;
    }

    private static String ecAlg(ECPrivateKey key) {
        int field = key.getParams().getCurve().getField().getFieldSize();
        if (field == 256) return "ES256";
        if (field == 384) return "ES384";
        if (field == 521) return "ES512";
        return "";
    }

    private static int ecSize(ECPrivateKey key) {
        return (key.getParams().getCurve().getField().getFieldSize() + 7) / 8;
    }

    private static int ecSize(ECPublicKey key) {
        return (key.getParams().getCurve().getField().getFieldSize() + 7) / 8;
    }

    private static BigInteger uint(String value) {
        return new BigInteger(1, Codec.b64UrlDecode(value, "integer"));
    }

    private static String string(Object value) {
        return value instanceof String text ? text : null;
    }

    static byte[] p1363ToDer(byte[] signature, int size) {
        byte[] r = Arrays.copyOfRange(signature, 0, size);
        byte[] s = Arrays.copyOfRange(signature, size, size * 2);
        byte[] rb = derInt(r);
        byte[] sb = derInt(s);
        int len = rb.length + sb.length;
        byte[] out = new byte[2 + len];
        out[0] = 0x30;
        out[1] = (byte) len;
        System.arraycopy(rb, 0, out, 2, rb.length);
        System.arraycopy(sb, 0, out, 2 + rb.length, sb.length);
        return out;
    }

    static byte[] derToP1363(byte[] der, int size) {
        int pos = 2;
        if ((der[1] & 0x80) != 0) pos = 2 + (der[1] & 0x7f);
        int[] r = readDerInt(der, pos);
        int[] s = readDerInt(der, r[1]);
        byte[] out = new byte[size * 2];
        writeFixed(out, 0, der, r[0], r[1] - r[0] - unused(der, r), size);
        writeFixed(out, size, der, s[0], s[1] - s[0], size);
        return out;
    }

    private static void writeFixed(byte[] out, int at, byte[] der, int start, int len, int size) {
        int from = start;
        int n = len;
        if (n > 0 && der[from] == 0) {
            from++;
            n--;
        }
        if (n > size) n = size;
        System.arraycopy(der, from, out, at + (size - n), n);
    }

    private static int unused(byte[] der, int[] span) {
        return 0;
    }

    /** Returns [contentStart, nextPos]. */
    private static int[] readDerInt(byte[] der, int pos) {
        if (der[pos] != 0x02) throw new IllegalArgumentException("DER");
        int len = der[pos + 1] & 0xff;
        int start = pos + 2;
        if ((der[pos + 1] & 0x80) != 0) throw new IllegalArgumentException("DER length");
        return new int[] {start, start + len};
    }

    private static byte[] derInt(byte[] magnitude) {
        int i = 0;
        while (i < magnitude.length - 1 && magnitude[i] == 0) i++;
        boolean pad = (magnitude[i] & 0x80) != 0;
        int n = magnitude.length - i;
        byte[] out = new byte[2 + n + (pad ? 1 : 0)];
        out[0] = 0x02;
        out[1] = (byte) (n + (pad ? 1 : 0));
        System.arraycopy(magnitude, i, out, pad ? 3 : 2, n);
        return out;
    }

    public static Set<String> algorithms() {
        return ALGS.keySet();
    }
}
