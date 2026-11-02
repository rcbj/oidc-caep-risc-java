// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.oidc.ssf;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** CAEP, RISC, and SSF event types, and what an event's subject names. */
public final class Events {
    private static final String CAEP = "https://schemas.openid.net/secevent/caep/event-type/";
    private static final String RISC = "https://schemas.openid.net/secevent/risc/event-type/";
    private static final String SSF = "https://schemas.openid.net/secevent/ssf/event-type/";

    public static final Map<String, String> EVENT = new LinkedHashMap<>();
    public static final List<String> CAEP_EVENTS = new ArrayList<>();
    public static final List<String> RISC_EVENTS = new ArrayList<>();
    public static final List<String> DEFAULT_EVENTS_REQUESTED;
    public static final List<String> DEFAULT_ENDING_EVENTS;

    static {
        put("sessionRevoked", CAEP + "session-revoked");
        put("tokenClaimsChange", CAEP + "token-claims-change");
        put("credentialChange", CAEP + "credential-change");
        put("assuranceLevelChange", CAEP + "assurance-level-change");
        put("deviceComplianceChange", CAEP + "device-compliance-change");
        put("sessionEstablished", CAEP + "session-established");
        put("sessionPresented", CAEP + "session-presented");
        put("riskLevelChange", CAEP + "risk-level-change");
        put("accountCredentialChangeRequired", RISC + "account-credential-change-required");
        put("accountPurged", RISC + "account-purged");
        put("accountDisabled", RISC + "account-disabled");
        put("accountEnabled", RISC + "account-enabled");
        put("identifierChanged", RISC + "identifier-changed");
        put("identifierRecycled", RISC + "identifier-recycled");
        put("credentialCompromise", RISC + "credential-compromise");
        put("optIn", RISC + "opt-in");
        put("optOutInitiated", RISC + "opt-out-initiated");
        put("optOutCancelled", RISC + "opt-out-cancelled");
        put("optOutEffective", RISC + "opt-out-effective");
        put("recoveryActivated", RISC + "recovery-activated");
        put("recoveryInformationChanged", RISC + "recovery-information-changed");
        put("sessionsRevoked", RISC + "sessions-revoked");
        put("verification", SSF + "verification");
        put("streamUpdated", SSF + "stream-updated");
        DEFAULT_EVENTS_REQUESTED = List.of(
                EVENT.get("sessionRevoked"), EVENT.get("credentialChange"), EVENT.get("assuranceLevelChange"), EVENT.get("tokenClaimsChange"),
                EVENT.get("accountDisabled"), EVENT.get("accountEnabled"), EVENT.get("accountPurged"), EVENT.get("credentialCompromise"),
                EVENT.get("sessionsRevoked"), EVENT.get("accountCredentialChangeRequired"));
        DEFAULT_ENDING_EVENTS = List.of(
                EVENT.get("sessionRevoked"), EVENT.get("accountDisabled"), EVENT.get("accountPurged"),
                EVENT.get("credentialCompromise"), EVENT.get("sessionsRevoked"));
    }

    private Events() {}

    private static void put(String name, String uri) {
        EVENT.put(name, uri);
        if (uri.startsWith(CAEP)) CAEP_EVENTS.add(uri);
        if (uri.startsWith(RISC)) RISC_EVENTS.add(uri);
    }

    public static Map<String, Object> subjectOf(Object subId, String issuer) {
        Map<String, Object> subject = map(subId);
        if (subject == null) return Map.of();
        String format = string(present(subject, "format", "subject_type"));
        if ("complex".equals(format) || (format.isEmpty() && (subject.get("user") != null || subject.get("session") != null))) {
            Map<String, Object> user = simple(subject.get("user"), issuer);
            Map<String, Object> session = simple(subject.get("session"), issuer);
            Map<String, Object> out = new LinkedHashMap<>();
            if (user.get("sub") instanceof String person) out.put("person", person);
            if (user.get("email") instanceof String email) out.put("email", email);
            Object sessionId = session.get("opaque") != null ? session.get("opaque") : session.get("sub");
            if (sessionId instanceof String id && !id.isEmpty()) out.put("idpSession", id);
            return out;
        }
        Map<String, Object> one = simple(subject, issuer);
        Map<String, Object> out = new LinkedHashMap<>();
        if (one.get("sub") instanceof String person) out.put("person", person);
        if (one.get("email") instanceof String email) out.put("email", email);
        return out;
    }

    private static Map<String, Object> simple(Object identifier, String issuer) {
        Map<String, Object> document = map(identifier);
        if (document == null) return Map.of();
        String format = string(present(document, "format", "subject_type"));
        if ("iss_sub".equals(format) && document.get("sub") instanceof String sub && (document.get("iss") == null || issuer.equals(document.get("iss")))) {
            return mapOf("sub", sub);
        }
        if ("email".equals(format) && document.get("email") instanceof String email) return mapOf("email", email);
        if ("opaque".equals(format) && document.get("id") instanceof String id) return mapOf("opaque", id);
        if ("aliases".equals(format) && document.get("identifiers") instanceof List<?> identifiers) {
            Map<String, Object> merged = new LinkedHashMap<>();
            for (Object one : identifiers) merged.putAll(simple(one, issuer));
            return merged;
        }
        return Map.of();
    }

    private static Object present(Map<String, Object> document, String... names) {
        for (String name : names) if (document.containsKey(name) && document.get(name) != null) return document.get(name);
        return null;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> map(Object value) {
        if (value instanceof Map<?, ?> raw) {
            Map<String, Object> out = new LinkedHashMap<>();
            raw.forEach((key, item) -> out.put(String.valueOf(key), item));
            return out;
        }
        return null;
    }

    private static Map<String, Object> mapOf(String key, String value) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put(key, value);
        return out;
    }

    private static String string(Object value) {
        return value == null ? "" : String.valueOf(value);
    }
}
