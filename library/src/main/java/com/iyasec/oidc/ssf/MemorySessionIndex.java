// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.oidc.ssf;

import com.iyasec.oidc.RelyingParty;

import java.util.ArrayList;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Predicate;

/** Which local sessions belong to which person and which provider session. */
public final class MemorySessionIndex {
    private final LinkedHashMap<String, Map<String, Object>> sessions = new LinkedHashMap<>();
    private final int max;

    public MemorySessionIndex() {
        this(100_000);
    }

    public MemorySessionIndex(int maxSessions) {
        this.max = maxSessions;
    }

    public void add(Map<String, ?> session) {
        String localId = String.valueOf(session.get("localId"));
        if (sessions.size() >= max && !sessions.containsKey(localId)) {
            long now = System.currentTimeMillis();
            for (String key : new ArrayList<>(sessions.keySet())) {
                Object expires = sessions.get(key).get("expiresAt");
                if (expires != null && stamp(expires) <= now) sessions.remove(key);
            }
            while (sessions.size() >= max && !sessions.isEmpty()) sessions.remove(sessions.keySet().iterator().next());
        }
        Map<String, Object> stored = new LinkedHashMap<>();
        session.forEach((key, value) -> stored.put(key, value));
        if (stored.get("email") instanceof String email) stored.put("email", email.toLowerCase());
        sessions.put(localId, stored);
    }

    public void remove(String localId) {
        sessions.remove(localId);
    }

    public List<String> byPerson(String person) {
        return find(session -> person.equals(session.get("person")));
    }

    public List<String> byEmail(String email) {
        String wanted = email.toLowerCase();
        return find(session -> wanted.equals(session.get("email")));
    }

    public List<String> byIdpSession(String idpSession) {
        return find(session -> idpSession.equals(session.get("idpSession")));
    }

    public static Map<String, Object> trackedFromLogin(String localId, RelyingParty.Login login, Date expiresAt) {
        Map<String, Object> session = new LinkedHashMap<>();
        session.put("localId", localId);
        session.put("person", login.subject);
        if (login.email != null) session.put("email", login.email);
        if (login.sid != null) session.put("idpSession", login.sid);
        if (expiresAt != null) session.put("expiresAt", expiresAt);
        return session;
    }

    private List<String> find(Predicate<Map<String, Object>> match) {
        long now = System.currentTimeMillis();
        List<String> out = new ArrayList<>();
        for (String key : new ArrayList<>(sessions.keySet())) {
            Map<String, Object> value = sessions.get(key);
            if (value == null) continue;
            Object expires = value.get("expiresAt");
            if (expires != null && stamp(expires) <= now) {
                sessions.remove(key);
                continue;
            }
            if (match.test(value)) out.add(key);
        }
        return out;
    }

    private static long stamp(Object value) {
        if (value instanceof Date date) return date.getTime();
        if (value instanceof Number number) return number.longValue();
        return Long.parseLong(String.valueOf(value));
    }
}
