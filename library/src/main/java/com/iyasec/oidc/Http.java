// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.oidc;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import java.io.ByteArrayInputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Duration;
import java.util.Base64;
import java.util.Collection;
import java.util.Map;

/** One back-channel request. TLS is verified. Redirects are not followed. */
public final class Http {
    public static final int MAX_BYTES = 2 * 1024 * 1024;
    public static final int TIMEOUT_S = 15;

    private static final HttpClient PLAIN = HttpClient.newBuilder()
            .followRedirects(HttpClient.Redirect.NEVER)
            .connectTimeout(Duration.ofSeconds(TIMEOUT_S))
            .build();

    private Http() {}

    public record Result(int status, String contentType, String body) {}

    public static Result send(String url, String method, Map<String, String> headers, byte[] body, Map<String, String> tls, String code) {
        URI uri;
        try {
            uri = new URI(url);
        } catch (Exception err) {
            Caught.error(err);
            throw new OidcError(code, url + " is not an http(s) URL", err);
        }
        String scheme = uri.getScheme();
        if (!"http".equals(scheme) && !"https".equals(scheme) || uri.getHost() == null) {
            throw new OidcError(code, url + " is not an http(s) URL");
        }
        HttpRequest.Builder builder = HttpRequest.newBuilder(uri).timeout(Duration.ofSeconds(TIMEOUT_S));
        if (headers != null) {
            headers.forEach((name, value) -> {
                if (name != null && value != null && !"content-length".equalsIgnoreCase(name) && !"host".equalsIgnoreCase(name)) {
                    builder.header(name, value);
                }
            });
        }
        builder.method(method, body == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofByteArray(body));
        HttpClient client = client(tls, code, url);
        try {
            HttpResponse<byte[]> response = client.send(builder.build(), HttpResponse.BodyHandlers.ofByteArray());
            byte[] raw = response.body() == null ? new byte[0] : response.body();
            if (raw.length > MAX_BYTES) throw new OidcError(code, url + " answered more than " + MAX_BYTES + " bytes");
            String type = response.headers().firstValue("content-type").orElse("");
            return new Result(response.statusCode(), type, new String(raw, StandardCharsets.UTF_8));
        } catch (OidcError err) {
            throw err;
        } catch (HttpTimeoutException err) {
            Caught.error(err);
            throw new OidcError(code, url + " did not answer within " + TIMEOUT_S + " s", err);
        } catch (InterruptedException err) {
            Caught.error(err);
            Thread.currentThread().interrupt();
            throw new OidcError(code, url + ": " + err, err);
        } catch (Exception err) {
            Caught.error(err);
            String message = String.valueOf(err.getMessage());
            if (message.contains("exceed") || message.contains("capacity") || message.contains("limit")) {
                throw new OidcError(code, url + " answered more than " + MAX_BYTES + " bytes", err);
            }
            if (err.getCause() instanceof HttpTimeoutException) {
                throw new OidcError(code, url + " did not answer within " + TIMEOUT_S + " s", err);
            }
            throw new OidcError(code, url + ": " + err, err);
        }
    }

    private static HttpClient client(Map<String, String> tls, String code, String url) {
        if (tls == null || ((tls.get("ca") == null || tls.get("ca").isEmpty())
                && (tls.get("cert") == null || tls.get("key") == null))) {
            return PLAIN;
        }
        try {
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(keyManagers(tls.get("cert"), tls.get("key")), trustManagers(tls.get("ca")), null);
            return HttpClient.newBuilder()
                    .followRedirects(HttpClient.Redirect.NEVER)
                    .connectTimeout(Duration.ofSeconds(TIMEOUT_S))
                    .sslContext(context)
                    .build();
        } catch (OidcError err) {
            throw err;
        } catch (Exception err) {
            Caught.error(err);
            throw new OidcError(code, url + ": " + err, err);
        }
    }

    private static TrustManager[] trustManagers(String ca) throws Exception {
        TrustManagerFactory base = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        base.init((KeyStore) null);
        KeyStore store = KeyStore.getInstance(KeyStore.getDefaultType());
        store.load(null, null);
        int n = 0;
        for (TrustManager manager : base.getTrustManagers()) {
            if (manager instanceof X509TrustManager x509) {
                for (X509Certificate certificate : x509.getAcceptedIssuers()) {
                    store.setCertificateEntry("default-" + (n++), certificate);
                }
            }
        }
        if (ca != null && !ca.isEmpty()) {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            Collection<? extends Certificate> extra = factory.generateCertificates(new ByteArrayInputStream(ca.getBytes(StandardCharsets.UTF_8)));
            for (Certificate certificate : extra) store.setCertificateEntry("extra-" + (n++), certificate);
        }
        TrustManagerFactory factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        factory.init(store);
        return factory.getTrustManagers();
    }

    private static KeyManager[] keyManagers(String certPem, String keyPem) throws Exception {
        if (certPem == null || certPem.isEmpty() || keyPem == null || keyPem.isEmpty()) return null;
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        Collection<? extends Certificate> chain = factory.generateCertificates(new ByteArrayInputStream(certPem.getBytes(StandardCharsets.UTF_8)));
        Certificate[] certificates = chain.toArray(Certificate[]::new);
        PrivateKey key = privateKey(keyPem);
        KeyStore store = KeyStore.getInstance("PKCS12");
        store.load(null, null);
        store.setKeyEntry("client", key, new char[0], certificates);
        KeyManagerFactory managers = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        managers.init(store, new char[0]);
        return managers.getKeyManagers();
    }

    private static PrivateKey privateKey(String pem) throws Exception {
        String body = pem.replace("-----BEGIN PRIVATE KEY-----", "").replace("-----END PRIVATE KEY-----", "").replaceAll("\\s", "");
        byte[] der = Base64.getDecoder().decode(body);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(der);
        for (String algorithm : new String[] {"RSA", "EC", "Ed25519"}) {
            try {
                return KeyFactory.getInstance(algorithm).generatePrivate(spec);
            } catch (Exception ignored) {
                // The next algorithm name may accept this PKCS#8 key.
            }
        }
        throw new IllegalArgumentException("PKCS#8 private key");
    }
}
