// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.oidc;

import java.util.Map;

/** Reads a configuration file and says whether it names a confidential client. It does not print secrets. */
public final class Check {
    private Check() {}

    public static String usage() {
        return """
                oidc-caep-risc — a confidential OpenID Connect client

                Usage
                  java com.iyasec.oidc.Check check --config <file>   read the file and print the client, without its secret
                  java com.iyasec.oidc.Check help

                The library is RelyingParty, in com.iyasec.oidc.""";
    }

    public static void main(String[] args) {
        int status = run(args);
        if (status != 0) System.exit(status);
    }

    static int run(String[] argv) {
        String command = argv.length == 0 ? "help" : argv[0];
        if ("help".equals(command) || "--help".equals(command) || "-h".equals(command)) {
            System.out.println(usage());
            return 0;
        }
        if (!"check".equals(command)) {
            System.err.println("unknown command " + command + "\n" + usage());
            return 1;
        }
        String file = null;
        for (int i = 0; i < argv.length; i++) {
            if ("--config".equals(argv[i]) && i + 1 < argv.length) file = argv[i + 1];
        }
        if (file == null) {
            System.err.println("check needs --config <file>\n" + usage());
            return 1;
        }
        Map<String, Object> config;
        try {
            config = Config.readConfigFile(file);
        } catch (OidcError err) {
            System.err.println(err.getMessage());
            return 1;
        }
        Object metadata = config.get("metadataUrl");
        if (metadata == null && config.get("metadata") instanceof Map<?, ?> document) metadata = document.get("issuer");
        if (metadata == null) metadata = "(file)";
        Object ssf = config.get("ssf") instanceof Map<?, ?> block ? block.get("transmitter") : null;
        System.out.println("client_id:  " + config.get("clientId"));
        System.out.println("auth:       " + config.get("tokenEndpointAuthMethod"));
        System.out.println("redirect:   " + config.get("redirectUri"));
        System.out.println("scopes:     " + config.get("scopes"));
        System.out.println("metadata:   " + metadata);
        System.out.println("secret:     " + (config.get("clientSecret") != null ? "present" : "absent"));
        System.out.println("tls ca:     " + (config.get("tlsCa") != null ? "present" : "absent"));
        System.out.println("ssf:        " + (ssf == null ? "not configured" : ssf));
        return 0;
    }
}
