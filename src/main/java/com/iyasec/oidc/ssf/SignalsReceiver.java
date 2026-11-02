// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.oidc.ssf;

import com.iyasec.oidc.Discovery;
import com.iyasec.oidc.Http;
import com.iyasec.oidc.Jsons;
import com.iyasec.oidc.OidcError;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.TimeUnit;
import java.util.function.BiConsumer;
import java.util.function.Consumer;
import java.util.function.Supplier;
import java.util.regex.Pattern;

/** A Shared Signals receiver: one poll stream of CAEP and RISC events (RFC 8936). */
public final class SignalsReceiver {
    private static final String POLL_METHOD = "urn:ietf:rfc:8936";
    private static final Pattern REFRESH_KEYS = Pattern.compile("publishes no|does not verify");

    private final String transmitter;
    private final BiConsumer<List<String>, Map<String, Object>> onEnd;
    private final Map<String, String> tls;
    private final Supplier<Map<String, String>> headers;
    private final List<String> eventsRequested;
    private final List<String> endOn;
    private final String description;
    private final long pollIntervalMs;
    private final int maxEvents;
    private final Log log;
    private final MemorySessionIndex index;
    private Map<String, Object> config;
    private Map<String, Object> stream;
    private List<Map<String, Object>> keys = List.of();
    private long keysAt;
    private volatile boolean running;
    private final List<String> ack = new ArrayList<>();
    private final Map<String, Object> errs = new LinkedHashMap<>();
    private final Map<String, List<Consumer<Map<String, Object>>>> handlers = new LinkedHashMap<>();
    private final Object lock = new Object();
    private Inflight inflight;
    private final java.util.concurrent.CountDownLatch started = new java.util.concurrent.CountDownLatch(1);
    private volatile Thread loopThread;

    private SignalsReceiver(Builder builder) {
        if (builder.onEnd == null) throw new OidcError("config", "onEndSessions is required");
        if (builder.transmitter == null || !builder.transmitter.matches("https?://.*")) {
            throw new OidcError("config", "transmitter must be an http(s) URL");
        }
        this.transmitter = builder.transmitter.replaceAll("/+$", "");
        this.onEnd = builder.onEnd;
        this.tls = builder.tls == null ? Map.of() : builder.tls;
        this.headers = builder.headers;
        this.eventsRequested = List.copyOf(builder.eventsRequested == null ? Events.DEFAULT_EVENTS_REQUESTED : builder.eventsRequested);
        this.endOn = List.copyOf(builder.endOn == null ? Events.DEFAULT_ENDING_EVENTS : builder.endOn);
        this.description = builder.description;
        this.pollIntervalMs = builder.pollIntervalMs;
        this.maxEvents = builder.maxEvents;
        this.log = builder.log == null ? new PrintLog() : builder.log;
        this.index = builder.index == null ? new MemorySessionIndex() : builder.index;
    }

    public static Builder builder(String transmitter, BiConsumer<List<String>, Map<String, Object>> onEnd) {
        return new Builder(transmitter, onEnd);
    }

    public Map<String, Object> stream() {
        return stream;
    }

    public void track(Map<String, ?> session) {
        index.add(session);
    }

    public void untrack(String localId) {
        index.remove(localId);
    }

    public SignalsReceiver on(String eventType, Consumer<Map<String, Object>> handler) {
        handlers.computeIfAbsent(eventType, key -> new ArrayList<>()).add(handler);
        return this;
    }

    public void start() {
        if (running) return;
        config = discover();
        jwks(true);
        stream = ensureStream();
        Map<String, Object> delivery = map(stream.get("delivery"));
        if (delivery == null || !(delivery.get("endpoint_url") instanceof String)) {
            throw new OidcError("ssf", "the stream has no poll endpoint_url");
        }
        running = true;
        List<?> delivered = stream.get("events_delivered") instanceof List<?> items ? items : List.of();
        log.info("ssf: polling stream " + stream.get("stream_id") + " at " + delivery.get("endpoint_url") + ", delivering " + delivered.size() + " event type(s)");
        loopThread = new Thread(this::loop, "ssf-poll");
        loopThread.setDaemon(true);
        loopThread.start();
    }

    public void stop() {
        running = false;
        Thread thread = loopThread;
        if (thread != null && thread != Thread.currentThread()) {
            thread.interrupt();
            try {
                thread.join(20_000);
            } catch (InterruptedException err) {
                Thread.currentThread().interrupt();
            }
            if (loopThread == thread) loopThread = null;
        }
    }

    public boolean pollOnce() {
        Inflight current;
        synchronized (lock) {
            if (inflight == null || inflight.done.isDone()) {
                inflight = new Inflight();
                Inflight mine = inflight;
                Thread worker = new Thread(() -> {
                    try {
                        mine.done.complete(pollNow());
                    } catch (Throwable err) {
                        mine.done.completeExceptionally(err);
                    }
                }, "ssf-poll-once");
                worker.setDaemon(true);
                worker.start();
            }
            current = inflight;
        }
        try {
            return current.done.join();
        } catch (CompletionException err) {
            Throwable cause = err.getCause() == null ? err : err.getCause();
            if (cause instanceof RuntimeException runtime) throw runtime;
            if (cause instanceof Error error) throw error;
            throw new OidcError("ssf", String.valueOf(cause), cause);
        }
    }

    private void loop() {
        while (running) {
            long delay = pollIntervalMs;
            try {
                if (pollOnce()) delay = 0;
            } catch (Exception err) {
                log.warn("ssf: poll failed: " + err);
                delay = Math.min(pollIntervalMs * 4, 60_000);
            }
            if (!running) return;
            if (delay <= 0) continue;
            try {
                Thread.sleep(delay);
            } catch (InterruptedException err) {
                return;
            }
        }
    }

    private boolean pollNow() {
        String url = String.valueOf(map(stream.get("delivery")).get("endpoint_url"));
        List<String> pendingAck;
        Map<String, Object> pendingErrs;
        synchronized (ack) {
            pendingAck = new ArrayList<>(ack);
            ack.clear();
            pendingErrs = new LinkedHashMap<>(errs);
            errs.clear();
        }
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("maxEvents", maxEvents);
        body.put("returnImmediately", true);
        if (!pendingAck.isEmpty()) body.put("ack", pendingAck);
        if (!pendingErrs.isEmpty()) body.put("setErrs", pendingErrs);
        Answer answer = call("POST", url, body);
        if (answer.status != 200) {
            synchronized (ack) {
                List<String> newer = new ArrayList<>(pendingAck);
                newer.addAll(ack);
                ack.clear();
                ack.addAll(newer);
                pendingErrs.forEach(errs::putIfAbsent);
            }
            throw new OidcError("ssf", "the poll answered " + answer.status + ": " + clip(answer.json));
        }
        Map<String, Object> payload = map(answer.json);
        if (payload == null) payload = Map.of();
        Map<String, Object> sets = map(payload.get("sets"));
        if (sets == null) sets = Map.of();
        for (Map.Entry<String, Object> entry : sets.entrySet()) {
            String jti = entry.getKey();
            try {
                handle(jti, String.valueOf(entry.getValue()));
                synchronized (ack) {
                    ack.add(jti);
                }
            } catch (Exception err) {
                log.warn("ssf: SET " + jti + " refused: " + err);
                String code = err instanceof OidcError oidc && "signature".equals(oidc.code) ? "invalid_key" : "invalid_request";
                Map<String, Object> problem = new LinkedHashMap<>();
                problem.put("err", code);
                problem.put("description", String.valueOf(err.getMessage() == null ? err : err.getMessage()));
                synchronized (ack) {
                    errs.put(jti, problem);
                }
            }
        }
        return payload.get("moreAvailable") == Boolean.TRUE;
    }

    private void handle(String jti, String token) {
        Map<String, Object> verified;
        try {
            verified = SecEvent.verifyCompactJws(token, jwks(false));
        } catch (OidcError err) {
            if (!"signature".equals(err.code) || err.getMessage() == null || !REFRESH_KEYS.matcher(err.getMessage()).find()) throw err;
            verified = SecEvent.verifyCompactJws(token, jwks(true));
        }
        @SuppressWarnings("unchecked")
        Map<String, Object> header = (Map<String, Object>) verified.get("header");
        @SuppressWarnings("unchecked")
        Map<String, Object> payload = (Map<String, Object>) verified.get("payload");
        if (header.get("typ") != null && !"secevent+jwt".equalsIgnoreCase(String.valueOf(header.get("typ")))) {
            throw new OidcError("validation", "the SET's typ is " + header.get("typ"));
        }
        if (!String.valueOf(config.get("issuer")).equals(payload.get("iss"))) {
            throw new OidcError("validation", "the SET was issued by " + payload.get("iss") + ", not " + config.get("issuer"));
        }
        List<String> want = strings(stream.get("aud"));
        List<String> aud = strings(payload.get("aud"));
        if (!want.isEmpty() && aud.stream().noneMatch(want::contains)) {
            throw new OidcError("validation", "the SET is for " + String.join(", ", aud) + ", not this stream");
        }
        if (payload.get("jti") != null && !jti.equals(payload.get("jti"))) {
            throw new OidcError("validation", "the SET's jti is not the one it was delivered under");
        }
        Map<String, Object> events = map(payload.get("events"));
        if (events == null || events.isEmpty()) throw new OidcError("validation", "the SET carries no events");
        for (Map.Entry<String, Object> entry : events.entrySet()) {
            String eventType = entry.getKey();
            Map<String, Object> eventBody = map(entry.getValue());
            Object subId = payload.get("sub_id") != null ? payload.get("sub_id") : (eventBody == null ? null : eventBody.get("subject"));
            Map<String, Object> subject = Events.subjectOf(subId, String.valueOf(config.get("issuer")));
            List<String> sessions = sessionsFor(eventType, subject);
            boolean ends = endOn.contains(eventType) && !sessions.isEmpty();
            Map<String, Object> event = new LinkedHashMap<>();
            event.put("type", eventType);
            event.put("payload", eventBody == null ? Map.of() : eventBody);
            event.put("subject", subject);
            event.put("jti", jti);
            event.put("sessions", sessions);
            event.put("ended", ends);
            if (payload.get("iat") instanceof Number iat) event.put("iat", iat);
            if (payload.get("txn") instanceof String txn) event.put("txn", txn);
            if (ends) {
                try {
                    onEnd.accept(sessions, event);
                } catch (Exception err) {
                    log.error("ssf: onEndSessions threw for " + eventType + " (SET " + jti + " is still acknowledged): " + err);
                    event.put("ended", false);
                }
                if (event.get("ended") == Boolean.TRUE) for (String localId : sessions) index.remove(localId);
            }
            List<Consumer<Map<String, Object>>> called = new ArrayList<>();
            if (handlers.get(eventType) != null) called.addAll(handlers.get(eventType));
            if (handlers.get("*") != null) called.addAll(handlers.get("*"));
            for (Consumer<Map<String, Object>> handler : called) {
                try {
                    handler.accept(event);
                } catch (Exception err) {
                    log.error("ssf: a handler for " + eventType + " threw (SET " + jti + " is still acknowledged): " + err);
                }
            }
        }
    }

    private List<String> sessionsFor(String eventType, Map<String, Object> subject) {
        if (Events.EVENT.get("verification").equals(eventType) || Events.EVENT.get("streamUpdated").equals(eventType)) return List.of();
        if (subject.get("idpSession") instanceof String idp) {
            List<String> found = index.byIdpSession(idp);
            if (!found.isEmpty() || Events.EVENT.get("sessionRevoked").equals(eventType)) return found;
        }
        if (subject.get("person") instanceof String person) return index.byPerson(person);
        if (subject.get("email") instanceof String email) return index.byEmail(email);
        return List.of();
    }

    public void verify(String state) {
        Object endpoint = config == null ? null : config.get("verification_endpoint");
        if (!(endpoint instanceof String url)) throw new OidcError("ssf", "the transmitter publishes no verification_endpoint");
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("stream_id", stream.get("stream_id"));
        if (state != null && !state.isEmpty()) body.put("state", state);
        Answer answer = call("POST", url, body);
        if (answer.status != 200 && answer.status != 204) throw new OidcError("ssf", "verification answered " + answer.status);
    }

    private Map<String, Object> discover() {
        List<String> urls = Discovery.wellKnownUrls(transmitter, "ssf-configuration");
        OidcError last = new OidcError("ssf", "no transmitter configuration at " + String.join(" or ", urls));
        for (int i = 0; i < urls.size(); i++) {
            String url = urls.get(i);
            Answer answer = call("GET", url, null);
            Map<String, Object> doc = map(answer.json);
            if (answer.status == 404 && i < urls.size() - 1) continue;
            if (answer.status != 200 || doc == null || !text(doc.get("configuration_endpoint")) || !text(doc.get("jwks_uri"))) {
                last = new OidcError("ssf", url + " answered " + answer.status + " without a usable transmitter configuration");
                continue;
            }
            if (doc.get("delivery_methods_supported") instanceof List<?> methods && !methods.isEmpty() && !methods.contains(POLL_METHOD)) {
                throw new OidcError("ssf", "the transmitter does not offer poll delivery (RFC 8936)");
            }
            return doc;
        }
        throw last;
    }

    private List<Map<String, Object>> jwks(boolean force) {
        if (!force && keys != null && !keys.isEmpty() && (System.currentTimeMillis() / 1000.0) - keysAt < 3600) return keys;
        Answer answer = call("GET", String.valueOf(config.get("jwks_uri")), null);
        List<Object> raw = map(answer.json) == null ? null : list(map(answer.json).get("keys"));
        if (answer.status != 200 || raw == null) throw new OidcError("ssf", "the transmitter's JWKS answered " + answer.status);
        List<Map<String, Object>> parsed = new ArrayList<>();
        for (Object item : raw) {
            Map<String, Object> jwk = map(item);
            if (jwk != null) parsed.add(jwk);
        }
        keys = parsed;
        keysAt = System.currentTimeMillis() / 1000;
        return keys;
    }

    private Map<String, Object> ensureStream() {
        String endpoint = String.valueOf(config.get("configuration_endpoint"));
        Answer listed = call("GET", endpoint, null);
        if (listed.status == 200) {
            List<Object> all = list(listed.json);
            if (all == null) all = listed.json == null ? List.of() : List.of(listed.json);
            for (Object item : all) {
                Map<String, Object> candidate = map(item);
                Map<String, Object> delivery = candidate == null ? null : map(candidate.get("delivery"));
                if (candidate != null && delivery != null && POLL_METHOD.equals(delivery.get("method")) && text(candidate.get("stream_id"))) {
                    return candidate;
                }
            }
        } else if (listed.status != 404) {
            throw new OidcError("ssf", "listing the streams at " + endpoint + " answered " + listed.status + ": " + clip(listed.json));
        }
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("delivery", Map.of("method", POLL_METHOD));
        body.put("events_requested", eventsRequested);
        if (description != null && !description.isEmpty()) body.put("description", description);
        Answer created = call("POST", endpoint, body);
        Map<String, Object> stream = map(created.json);
        if ((created.status != 200 && created.status != 201) || stream == null || !text(stream.get("stream_id"))) {
            throw new OidcError("ssf", "creating a stream at " + endpoint + " answered " + created.status + ": " + clip(created.json));
        }
        return stream;
    }

    private Answer call(String method, String url, Object body) {
        Map<String, String> requestHeaders = new LinkedHashMap<>();
        requestHeaders.put("accept", "application/json");
        if (headers != null) {
            Map<String, String> extra = headers.get();
            if (extra != null) requestHeaders.putAll(extra);
        }
        byte[] payload = null;
        if (body != null) {
            requestHeaders.put("content-type", "application/json");
            payload = Jsons.write(body).getBytes(StandardCharsets.UTF_8);
        }
        Http.Result answer = Http.send(url, method, requestHeaders, payload, tls, "ssf");
        Object parsed = null;
        if (answer.body() != null && !answer.body().isEmpty()) {
            try {
                parsed = Jsons.read(answer.body());
            } catch (IllegalArgumentException err) {
                parsed = answer.body();
            }
        }
        return new Answer(answer.status(), parsed);
    }

    private static String clip(Object value) {
        String text;
        try {
            text = Jsons.write(value);
        } catch (Exception err) {
            text = String.valueOf(value);
        }
        return text.length() > 300 ? text.substring(0, 300) : text;
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

    @SuppressWarnings("unchecked")
    private static List<Object> list(Object value) {
        return value instanceof List<?> raw ? (List<Object>) raw : null;
    }

    private static List<String> strings(Object value) {
        if (value instanceof List<?> items) {
            List<String> out = new ArrayList<>();
            for (Object item : items) out.add(String.valueOf(item));
            return out;
        }
        if (value == null) return List.of();
        return List.of(String.valueOf(value));
    }

    private static boolean text(Object value) {
        return value instanceof String string && !string.isEmpty();
    }

    public interface Log {
        void info(String message);
        void warn(String message);
        void error(String message);
    }

    private static final class PrintLog implements Log {
        public void info(String message) { System.out.println(message); }
        public void warn(String message) { System.out.println(message); }
        public void error(String message) { System.out.println(message); }
    }

    private static final class Inflight {
        final CompletableFuture<Boolean> done = new CompletableFuture<>();
    }

    private record Answer(int status, Object json) {}

    public static final class Builder {
        private final String transmitter;
        private final BiConsumer<List<String>, Map<String, Object>> onEnd;
        private Map<String, String> tls;
        private Supplier<Map<String, String>> headers;
        private List<String> eventsRequested;
        private List<String> endOn;
        private MemorySessionIndex index;
        private String description;
        private long pollIntervalMs = 5000;
        private int maxEvents = 50;
        private Log log;

        private Builder(String transmitter, BiConsumer<List<String>, Map<String, Object>> onEnd) {
            this.transmitter = transmitter;
            this.onEnd = onEnd;
        }

        public Builder tls(Map<String, String> tls) { this.tls = tls; return this; }
        public Builder headers(Supplier<Map<String, String>> headers) { this.headers = headers; return this; }
        public Builder eventsRequested(List<String> events) { this.eventsRequested = events; return this; }
        public Builder endOn(List<String> events) { this.endOn = events; return this; }
        public Builder sessionIndex(MemorySessionIndex index) { this.index = index; return this; }
        public Builder description(String description) { this.description = description; return this; }
        public Builder pollIntervalMs(long pollIntervalMs) { this.pollIntervalMs = pollIntervalMs; return this; }
        public Builder maxEvents(int maxEvents) { this.maxEvents = maxEvents; return this; }
        public Builder log(Log log) { this.log = log; return this; }
        public SignalsReceiver build() { return new SignalsReceiver(this); }
    }
}
