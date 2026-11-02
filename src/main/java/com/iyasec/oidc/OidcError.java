// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.oidc;

/** A failure from configuration, discovery, the protocol, validation, a signature, or Shared Signals. */
public class OidcError extends RuntimeException {
    public final String code;
    public final String oauthError;

    public OidcError(String code, String message) {
        this(code, message, null, null);
    }

    public OidcError(String code, String message, Throwable cause) {
        this(code, message, cause, null);
    }

    public OidcError(String code, String message, Throwable cause, String oauthError) {
        super(message, cause);
        this.code = code;
        this.oauthError = oauthError;
    }
}
