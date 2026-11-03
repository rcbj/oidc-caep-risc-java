// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.oidc;

/**
 * The tokens of one sign-in as a {@link SessionStore} keeps them. Every field
 * is a string or a number, so a shared store can write it anywhere.
 *
 * @param subject the ID token's {@code sub}
 * @param accessToken the access token
 * @param tokenType {@code DPoP} or {@code Bearer}
 * @param refreshToken the refresh token, or null
 * @param idToken the latest ID token
 * @param expiresAt when the access token expires, in milliseconds since the
 *        epoch; 0 when the provider did not say
 * @param scope the granted scope, or null
 */
public record SessionTokens(String subject, String accessToken, String tokenType, String refreshToken,
                            String idToken, long expiresAt, String scope) {
}
