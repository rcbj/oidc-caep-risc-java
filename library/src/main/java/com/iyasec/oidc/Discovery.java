// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.oidc;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** OpenID Provider discovery for a confidential Authorization Code client. */
public final class Discovery {
    public static final List<String> ASYMMETRIC_JWS_ALGS = List.copyOf(JwsCrypto.SUPPORTED);
    public static final String DEFAULT_SCOPES = "openid profile email offline_access ssf.read ssf.manage";

    private static final List<String> REQUIRED = List.of(
            "issuer", "authorization_endpoint", "token_endpoint", "jwks_uri",
            "response_types_supported", "subject_types_supported", "id_token_signing_alg_values_supported");

    private Discovery() {}

    public static String issuerFromMetadataUrl(String metadataUrl) {
        URI uri = parse(metadataUrl);
        if (uri == null || (!"http".equals(uri.getScheme()) && !"https".equals(uri.getScheme())) || uri.getRawAuthority() == null) {
            throw new OidcError("config", "metadataUrl is not a URL: " + metadataUrl);
        }
        String path = uri.getRawPath() == null ? "" : uri.getRawPath();
        String marker = "/.well-known/openid-configuration";
        int at = path.indexOf(marker);
        if (at < 0) throw new OidcError("config", "metadataUrl must be the openid-configuration URL, not " + metadataUrl);
        String prefix = path.substring(0, at).replaceAll("/+$", "");
        return uri.getScheme() + "://" + uri.getRawAuthority() + prefix;
    }

    public static Map<String, Object> validateProviderMetadata(Object raw, String expectedIssuer) {
        Map<String, Object> doc = Jsons.map(raw);
        if (doc == null) throw new OidcError("discovery", "OpenID Provider metadata must be a JSON object");
        List<String> missing = new ArrayList<>();
        for (String key : REQUIRED) if (!doc.containsKey(key)) missing.add(key);
        if (!missing.isEmpty()) throw new OidcError("discovery", "OpenID Provider metadata is missing " + String.join(", ", missing));
        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("issuer", mustBeUrl(doc.get("issuer"), "issuer"));
        metadata.put("authorization_endpoint", mustBeUrl(doc.get("authorization_endpoint"), "authorization_endpoint"));
        metadata.put("token_endpoint", mustBeUrl(doc.get("token_endpoint"), "token_endpoint"));
        metadata.put("jwks_uri", mustBeUrl(doc.get("jwks_uri"), "jwks_uri"));
        metadata.put("response_types_supported", doc.get("response_types_supported"));
        metadata.put("subject_types_supported", doc.get("subject_types_supported"));
        metadata.put("id_token_signing_alg_values_supported", doc.get("id_token_signing_alg_values_supported"));
        for (String key : List.of("userinfo_endpoint", "end_session_endpoint", "pushed_authorization_request_endpoint", "revocation_endpoint")) {
            if (doc.containsKey(key) && doc.get(key) != null) metadata.put(key, mustBeUrl(doc.get(key), key));
        }
        for (String key : List.of("token_endpoint_auth_methods_supported", "code_challenge_methods_supported", "scopes_supported", "grant_types_supported")) {
            if (doc.containsKey(key) && doc.get(key) != null) {
                List<Object> items = Jsons.list(doc.get(key));
                if (items == null) throw new OidcError("discovery", key + " must be an array");
                metadata.put(key, strings(items));
            }
        }
        if (doc.containsKey("authorization_response_iss_parameter_supported") && doc.get("authorization_response_iss_parameter_supported") != null) {
            metadata.put("authorization_response_iss_parameter_supported", doc.get("authorization_response_iss_parameter_supported") == Boolean.TRUE);
        }
        List<Object> responseTypes = Jsons.list(metadata.get("response_types_supported"));
        if (responseTypes == null || !strings(responseTypes).contains("code")) {
            throw new OidcError("discovery", "OpenID Provider does not support response_type=code");
        }
        metadata.put("response_types_supported", strings(responseTypes));
        List<Object> subjects = Jsons.list(metadata.get("subject_types_supported"));
        if (subjects == null) throw new OidcError("discovery", "subject_types_supported must be an array");
        metadata.put("subject_types_supported", strings(subjects));
        List<Object> algs = Jsons.list(metadata.get("id_token_signing_alg_values_supported"));
        if (algs == null) throw new OidcError("discovery", "id_token_signing_alg_values_supported must be an array");
        metadata.put("id_token_signing_alg_values_supported", strings(algs));
        if (expectedIssuer != null && !expectedIssuer.equals(metadata.get("issuer"))) {
            throw new OidcError("discovery", "issuer mismatch: expected \"" + expectedIssuer + "\", got \"" + metadata.get("issuer") + "\"");
        }
        return metadata;
    }

    public static Map<String, Object> discoverProvider(String metadataUrl, Map<String, String> tls) {
        String expected = issuerFromMetadataUrl(metadataUrl);
        Http.Result answer = Http.send(metadataUrl, "GET", Map.of("accept", "application/json"), null, tls, "discovery");
        if (answer.status() != 200) throw new OidcError("discovery", metadataUrl + " answered " + answer.status());
        Object body;
        try {
            body = Jsons.read(answer.body());
        } catch (Exception err) {
            Caught.error(err);
            throw new OidcError("discovery", metadataUrl + " did not answer JSON", err);
        }
        return validateProviderMetadata(body, expected);
    }

    public static List<String> wellKnownUrls(String issuer, String suffix) {
        URI uri = URI.create(issuer);
        String path = uri.getRawPath() == null ? "" : uri.getRawPath().replaceAll("/+$", "");
        String origin = uri.getScheme() + "://" + uri.getRawAuthority();
        String inserted = origin + "/.well-known/" + suffix + path;
        String appended = origin + path + "/.well-known/" + suffix;
        if (inserted.equals(appended)) return List.of(inserted);
        return List.of(inserted, appended);
    }

    public static List<String> idTokenAlgorithms(List<?> advertised, String pinned) {
        List<String> names = new ArrayList<>();
        if (advertised != null) for (Object item : advertised) names.add(String.valueOf(item));
        if (pinned != null && !pinned.isEmpty()) {
            if (!names.contains(pinned)) throw new OidcError("discovery", "the provider does not advertise id_token alg " + pinned);
            return List.of(pinned);
        }
        List<String> allowed = new ArrayList<>();
        for (String alg : names) if (ASYMMETRIC_JWS_ALGS.contains(alg)) allowed.add(alg);
        if (allowed.isEmpty()) {
            throw new OidcError("discovery", "none of the provider's ID token algorithms can be verified (" + String.join(", ", names) + ")");
        }
        return allowed;
    }

    private static String mustBeUrl(Object value, String name) {
        if (!(value instanceof String text) || text.isEmpty()) {
            throw new OidcError("discovery", "OpenID Provider metadata " + name + " is missing");
        }
        URI uri = parse(text);
        if (uri == null || (!"http".equals(uri.getScheme()) && !"https".equals(uri.getScheme())) || uri.getHost() == null) {
            throw new OidcError("discovery", "OpenID Provider metadata " + name + " is not a valid URL");
        }
        boolean query = uri.getRawQuery() != null && !uri.getRawQuery().isEmpty();
        boolean fragment = uri.getRawFragment() != null && !uri.getRawFragment().isEmpty();
        if ("issuer".equals(name) && (query || fragment)) {
            throw new OidcError("discovery", "issuer must not contain a query or fragment");
        }
        return text;
    }

    private static List<String> strings(List<Object> items) {
        List<String> out = new ArrayList<>();
        for (Object item : items) out.add(String.valueOf(item));
        return out;
    }

    private static URI parse(String value) {
        try {
            return new URI(value);
        } catch (Exception err) {
            Caught.warn(err);
            return null;
        }
    }

    static String scheme(String value) {
        String text = value != null && value.startsWith("http") ? value : "https://" + value;
        URI uri = parse(text);
        return uri == null || uri.getScheme() == null ? "" : uri.getScheme();
    }

    static byte[] bytes(String text) {
        return text.getBytes(StandardCharsets.UTF_8);
    }
}
