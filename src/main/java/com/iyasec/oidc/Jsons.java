// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.oidc;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** JSON objects keep the order they were written in. */
public final class Jsons {
    public static final ObjectMapper MAPPER = new ObjectMapper();
    private static final TypeReference<Object> ANY = new TypeReference<>() {};

    private Jsons() {}

    public static Object read(String text) {
        try {
            return MAPPER.readValue(text, ANY);
        } catch (Exception err) {
            throw new IllegalArgumentException(err.getMessage(), err);
        }
    }

    public static String write(Object value) {
        try {
            return MAPPER.writeValueAsString(value);
        } catch (Exception err) {
            throw new IllegalArgumentException(err.getMessage(), err);
        }
    }

    @SuppressWarnings("unchecked")
    public static Map<String, Object> map(Object value) {
        if (value instanceof Map<?, ?> raw) {
            Map<String, Object> out = new LinkedHashMap<>();
            raw.forEach((key, item) -> out.put(String.valueOf(key), item));
            return out;
        }
        return null;
    }

    @SuppressWarnings("unchecked")
    public static List<Object> list(Object value) {
        if (value instanceof List<?> raw) return (List<Object>) raw;
        return null;
    }
}
