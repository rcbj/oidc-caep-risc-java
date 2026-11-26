// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.oidc;

import com.fasterxml.jackson.databind.JsonNode;
import com.iyasec.pep.Mode;
import com.iyasec.pep.Pep;
import com.iyasec.pep.PepConfig;
import com.iyasec.pep.PepException;
import com.iyasec.pep.Subject;
import com.iyasec.pep.key.SigningKey;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * The embedded iya-sts PEP. The PEP is {@code com.iyasec:iya-pep}; this
 * library only wires it. A {@code pep} section is off unless present.
 * {@code pdpUrl} defaults to the provider's issuer and {@code application}
 * to {@code clientId}. The assertion key must not be the
 * {@code private_key_jwt} key or the DPoP key. A sign-in becomes the
 * subject: {@code username}, else {@code preferred_username}, else
 * {@code sub}, with the ID token claims as properties.
 */
public final class PepWiring {
    private PepWiring() {}

    /**
     * Builds the PEP from the configuration's {@code pep} section.
     *
     * @param config the relying party's configuration
     * @param metadata the provider's metadata
     * @param dpop the live DPoP signer, or null when DPoP is not in use
     * @return the PEP, or null when there is no section
     */
    static Pep build(Map<String, Object> config, Map<String, Object> metadata, Dpop dpop) {
        Object section = config.get("pep");
        if (section == null) return null;
        Map<String, Object> given = Jsons.map(section);
        if (given == null) throw new OidcError("config", "pep must be an object");
        Map<String, Object> map = new LinkedHashMap<>(given);
        // The library's own values, unless the section names its own.
        if (!map.containsKey("signals")) map.put("signals", config.get("signals") != Boolean.FALSE);
        if (!map.containsKey("tlsCa") && config.get("tlsCa") instanceof String ca && ca.contains("-----BEGIN")) {
            map.put("tlsCa", ca);
        }
        String fromMetadata = metadata == null || metadata.get("issuer") == null ? "" : String.valueOf(metadata.get("issuer"));
        String issuer = fromMetadata.isEmpty()
                ? (config.get("issuer") == null ? "" : String.valueOf(config.get("issuer")))
                : fromMetadata;
        String clientId = config.get("clientId") == null ? "" : String.valueOf(config.get("clientId"));
        Pep pep;
        try {
            pep = Pep.create(PepConfig.fromJson(Jsons.MAPPER.valueToTree(map), issuer, clientId));
        } catch (PepException err) {
            throw new OidcError("config", err.detail(), err);
        }
        String thumb = pep.keyThumbprint();
        if (config.get("privateKeyPem") instanceof String pem && !pem.isEmpty()) {
            String own = SigningKey.pemThumbprint(pem);
            if (thumb != null && thumb.equals(own)) {
                throw new OidcError("config", "pep.assertionKey is the private_key_jwt key; the PEP needs a key of its own");
            }
        }
        if (dpop != null && thumb != null && thumb.equals(dpop.thumbprint())) {
            throw new OidcError("config", "pep.assertionKey is the DPoP key; the PEP needs a key of its own");
        }
        return pep;
    }

    /**
     * The PEP's subject for a sign-in.
     *
     * @param login the sign-in
     * @return the subject
     */
    public static Subject subjectOf(RelyingParty.Login login) {
        return subjectWithUserinfo(login, Map.of());
    }

    /**
     * {@link #subjectOf}, with userinfo claims laid over the ID token's.
     *
     * @param login the sign-in
     * @param userinfo claims the application fetched, or an empty map
     * @return the subject
     */
    public static Subject subjectWithUserinfo(RelyingParty.Login login, Map<String, ?> userinfo) {
        return Subject.user(subjectId(login), claims(propertiesOf(login, userinfo)));
    }

    /**
     * The username ({@code username}, else {@code preferred_username}, else
     * {@code sub}). An empty claim is skipped.
     *
     * @param login the sign-in
     * @return the subject id
     */
    static String subjectId(RelyingParty.Login login) {
        Object username = login.claims == null ? null : login.claims.get("username");
        if (username instanceof String text && !text.isEmpty()) return text;
        if (login.preferredUsername != null && !login.preferredUsername.isEmpty()) return login.preferredUsername;
        return login.subject == null ? "" : login.subject;
    }

    /**
     * ID token claims, with {@code userinfo} laid over them.
     *
     * @param login the sign-in
     * @param userinfo claims the application fetched, or null
     * @return a new map
     */
    static Map<String, Object> propertiesOf(RelyingParty.Login login, Map<String, ?> userinfo) {
        Map<String, Object> properties = new LinkedHashMap<>();
        if (login.claims != null) properties.putAll(login.claims);
        if (userinfo != null) userinfo.forEach(properties::put);
        return properties;
    }

    /** Claims as JSON values, which is what {@link Subject#user} stores. */
    private static Map<String, JsonNode> claims(Map<String, Object> properties) {
        Map<String, JsonNode> claims = new LinkedHashMap<>();
        properties.forEach((name, value) -> claims.put(name, Jsons.MAPPER.valueToTree(value)));
        return claims;
    }

    /**
     * Whether a receiver built with this PEP asks for
     * {@code pep-policies-changed}: {@code local}, or {@code central} with a
     * Permit cache.
     *
     * @param pep the PEP
     * @return true when the event is wanted
     */
    public static boolean wantsEvents(Pep pep) {
        return pep.config().mode == Mode.LOCAL || pep.config().permitCacheMs > 0;
    }
}
