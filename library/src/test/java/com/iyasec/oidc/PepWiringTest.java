// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.oidc;

import com.iyasec.pep.Mode;
import com.iyasec.pep.Pep;
import com.iyasec.pep.PepConfig;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The embedded PEP's configuration, key separation and subject. The PEP's own behaviour is iya-pep's suite. */
class PepWiringTest {
    @Test
    void aFileKeepsThePepSectionAndAddSubjects() {
        Map<String, Object> raw = new LinkedHashMap<>();
        raw.put("clientId", "app");
        raw.put("clientSecret", "secret");
        raw.put("redirectUri", "https://app.example/callback");
        raw.put("metadataUrl", "https://idp.example/.well-known/openid-configuration");
        raw.put("scopes", "openid");
        Map<String, Object> pep = new LinkedHashMap<>();
        pep.put("name", "pep-demo");
        pep.put("mode", "central");
        raw.put("pep", pep);
        Map<String, Object> ssf = new LinkedHashMap<>();
        ssf.put("transmitter", "https://idp.example");
        ssf.put("addSubjects", false);
        raw.put("ssf", ssf);
        Map<String, Object> out = Config.resolveConfig(raw, "/tmp");
        assertEquals("pep-demo", Jsons.map(out.get("pep")).get("name"));
        assertEquals("central", Jsons.map(out.get("pep")).get("mode"));
        assertEquals(Boolean.FALSE, Jsons.map(out.get("ssf")).get("addSubjects"));
    }

    @Test
    void addSubjectsMustBeABoolean() {
        Map<String, Object> given = new LinkedHashMap<>();
        given.put("redirectUri", "https://app.example/callback");
        Map<String, Object> ssf = new LinkedHashMap<>();
        ssf.put("addSubjects", "no");
        given.put("ssf", ssf);
        OidcError err = assertThrows(OidcError.class, () -> Config.normalize(given));
        assertTrue(err.getMessage().contains("ssf.addSubjects must be true or false"));
    }

    @Test
    void noSectionBuildsNoPepAndABadSectionIsRefused() {
        RelyingParty plain = RelyingParty.create(party(null));
        assertNull(plain.pep());
        OidcError err = assertThrows(OidcError.class, () -> RelyingParty.create(party("on")));
        assertEquals("config", err.code);
        assertTrue(err.getMessage().contains("pep must be an object"));
    }

    @Test
    void thePepKeyMustDifferFromTheRelyingPartysKeys() throws Exception {
        String pem = pemOf(ec());
        Path file = Files.createTempFile("oidc-pep-same-", ".pem");
        file.toFile().deleteOnExit();
        Files.writeString(file, pem);
        Map<String, Object> section = section(file);
        Map<String, Object> asPrivateKey = party(section);
        asPrivateKey.put("tokenEndpointAuthMethod", "private_key_jwt");
        asPrivateKey.remove("clientSecret");
        asPrivateKey.put("privateKeyPem", pem);
        asPrivateKey.put("privateKeyAlg", "ES256");
        asPrivateKey.put("dpop", "never");
        OidcError sameKey = assertThrows(OidcError.class, () -> RelyingParty.create(asPrivateKey));
        assertEquals("config", sameKey.code);
        assertEquals("pep.assertionKey is the private_key_jwt key; the PEP needs a key of its own", sameKey.getMessage());

        Map<String, Object> asDpop = party(section);
        asDpop.put("dpop", "always");
        asDpop.put("dpopKey", pem);
        @SuppressWarnings("unchecked")
        Map<String, Object> metadata = (Map<String, Object>) asDpop.get("metadata");
        metadata.put("dpop_signing_alg_values_supported", List.of("ES256"));
        OidcError sameDpop = assertThrows(OidcError.class, () -> RelyingParty.create(asDpop));
        assertEquals("pep.assertionKey is the DPoP key; the PEP needs a key of its own", sameDpop.getMessage());
    }

    @Test
    void theSubjectIdIsUsernameThenPreferredUsernameThenSub() {
        RelyingParty.Login login = login("0b6e-uuid", "alice");
        login.claims.put("username", "alice-dir");
        assertEquals("alice-dir", PepWiring.subjectId(login));
        login.claims.put("username", "");
        assertEquals("alice", PepWiring.subjectId(login));
        login.preferredUsername = "";
        assertEquals("0b6e-uuid", PepWiring.subjectId(login));
        Map<String, Object> over = PepWiring.propertiesOf(login, Map.of("email", "a@x.test", "sub", "0b6e-uuid"));
        assertEquals("a@x.test", over.get("email"));
        assertEquals("urn:example:mfa", over.get("acr"));
    }

    @Test
    void localAndAPermitCacheAskForEvents() throws Exception {
        Path file = Files.createTempFile("oidc-pep-events-", ".pem");
        file.toFile().deleteOnExit();
        Files.writeString(file, pemOf(ec()));
        Pep local = Pep.create(PepConfig.fromJson(Jsons.MAPPER.valueToTree(section(file)), "https://idp.example", "app"));
        assertEquals(Mode.LOCAL, local.config().mode);
        assertTrue(PepWiring.wantsEvents(local));
        Map<String, Object> central = section(file);
        central.put("mode", "central");
        Pep noCache = Pep.create(PepConfig.fromJson(Jsons.MAPPER.valueToTree(central), "https://idp.example", "app"));
        assertFalse(PepWiring.wantsEvents(noCache));
        central.put("permitCacheMs", 1000);
        Pep cached = Pep.create(PepConfig.fromJson(Jsons.MAPPER.valueToTree(central), "https://idp.example", "app"));
        assertTrue(PepWiring.wantsEvents(cached));
    }

    private static Map<String, Object> section(Path key) {
        Map<String, Object> section = new LinkedHashMap<>();
        section.put("name", "pep-demo");
        section.put("mode", "local");
        section.put("assertionKey", key.toString());
        section.put("pdpUrl", "https://idp.example");
        section.put("signals", false);
        return section;
    }

    private static Map<String, Object> party(Object pep) {
        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("issuer", "https://idp.example");
        metadata.put("authorization_endpoint", "https://idp.example/oauth2/authorize");
        metadata.put("token_endpoint", "https://idp.example/oauth2/token");
        metadata.put("jwks_uri", "https://idp.example/jwks");
        metadata.put("id_token_signing_alg_values_supported", List.of("RS256"));
        metadata.put("token_endpoint_auth_methods_supported", List.of("client_secret_basic", "private_key_jwt"));
        Map<String, Object> doc = new LinkedHashMap<>();
        doc.put("issuer", "https://idp.example");
        doc.put("metadata", metadata);
        doc.put("clientId", "app");
        doc.put("clientSecret", "secret");
        doc.put("tokenEndpointAuthMethod", "client_secret_basic");
        doc.put("redirectUri", "https://app.example/callback");
        doc.put("dpop", "never");
        if (pep != null) doc.put("pep", pep);
        return doc;
    }

    private static RelyingParty.Login login(String sub, String username) {
        RelyingParty.Login login = new RelyingParty.Login();
        login.subject = sub;
        login.preferredUsername = username;
        login.claims = new LinkedHashMap<>();
        login.claims.put("sub", sub);
        login.claims.put("preferred_username", username);
        login.claims.put("acr", "urn:example:mfa");
        return login;
    }

    private static byte[] ec() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        return generator.generateKeyPair().getPrivate().getEncoded();
    }

    private static String pemOf(byte[] der) {
        return "-----BEGIN PRIVATE KEY-----\n" + Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(der) + "\n-----END PRIVATE KEY-----\n";
    }
}
