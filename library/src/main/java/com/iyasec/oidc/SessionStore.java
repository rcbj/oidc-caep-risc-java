// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.oidc;

/**
 * Where the relying party keeps the tokens of a completed sign-in, keyed by a
 * session identifier the application chooses. The default is
 * {@link MemorySessionStore}; an application that runs several processes
 * replaces it with a shared store.
 */
public interface SessionStore {
    /**
     * The tokens kept for a session.
     *
     * @param sessionId the application's session identifier
     * @return the tokens, or null when there are none
     */
    SessionTokens get(String sessionId);

    /**
     * Keep (or replace) the tokens for a session.
     *
     * @param sessionId the application's session identifier
     * @param tokens the tokens
     */
    void put(String sessionId, SessionTokens tokens);

    /**
     * Forget a session's tokens. Removing a session that is not there is not
     * an error.
     *
     * @param sessionId the application's session identifier
     */
    void remove(String sessionId);
}
