// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.oidc;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/** The default {@link SessionStore}: this process's memory. */
public final class MemorySessionStore implements SessionStore {
    private final Map<String, SessionTokens> sessions = new ConcurrentHashMap<>();

    /** An empty store. */
    public MemorySessionStore() {}

    @Override
    public SessionTokens get(String sessionId) {
        return sessionId == null ? null : sessions.get(sessionId);
    }

    @Override
    public void put(String sessionId, SessionTokens tokens) {
        if (sessionId == null || tokens == null) return;
        sessions.put(sessionId, tokens);
    }

    @Override
    public void remove(String sessionId) {
        if (sessionId != null) sessions.remove(sessionId);
    }

    /**
     * How many sessions are kept.
     *
     * @return the number of entries
     */
    public int size() {
        return sessions.size();
    }
}
