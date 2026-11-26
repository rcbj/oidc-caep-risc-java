// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.oidc.ssf;

import com.iyasec.oidc.Caught;
import com.iyasec.oidc.Discovery;
import com.iyasec.oidc.Http;
import com.iyasec.oidc.Jsons;
import com.iyasec.oidc.OidcError;
import com.iyasec.oidc.PepWiring;
import com.iyasec.oidc.RelyingParty;
import com.iyasec.pep.EventStream;
import com.iyasec.pep.Pep;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ConcurrentHashMap;
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
    private final Transport transport;
    private final RelyingParty relyingParty;
    private final List<String> eventsRequested;
    private final List<String> endOn;
    private final String description;
    private final long pollIntervalMs;
    private final int maxEvents;
    private final Log log;
    private final Consumer<String> onError;
    private final boolean addSubjects;
    private final MemorySessionIndex index;
    /** Subjects the transmitter accepted, so Remove Subject is only for those. */
    private final Set<String> added = ConcurrentHashMap.newKeySet();
    /** {@code requested} or {@code excluded}, once known. A failed poll reports {@code down}. */
    private volatile EventStream pepStream;
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
        this.transport = builder.transport;
        this.relyingParty = builder.relyingParty;
        List<String> events = new ArrayList<>(builder.eventsRequested == null ? Events.DEFAULT_EVENTS_REQUESTED : builder.eventsRequested);
        Pep pep = pepWantingEvents(builder.relyingParty);
        if (pep != null && !events.contains(Pep.POLICIES_CHANGED_EVENT)) events.add(Pep.POLICIES_CHANGED_EVENT);
        this.eventsRequested = List.copyOf(events);
        this.endOn = List.copyOf(builder.endOn == null ? Events.DEFAULT_ENDING_EVENTS : builder.endOn);
        this.description = builder.description;
        this.pollIntervalMs = builder.pollIntervalMs;
        this.maxEvents = builder.maxEvents;
        this.log = builder.log == null ? new PrintLog() : builder.log;
        this.onError = builder.onError;
        this.addSubjects = builder.addSubjects && !subjectsConfiguredOff(builder.relyingParty);
        this.index = builder.index == null ? new MemorySessionIndex() : builder.index;
        if (pep != null) {
            // The SET was verified like every other before a handler sees it.
            // The PEP treats the event as a hint and pulls with its own token.
            on(Pep.POLICIES_CHANGED_EVENT, event -> {
                Object payload = event.get("payload");
                pep.onPolicyEvent(Jsons.MAPPER.valueToTree(payload == null ? Map.of() : payload));
            });
        }
    }

    /** The event types this receiver asks its stream for. */
    public List<String> eventsRequested() {
        return eventsRequested;
    }

    public static Builder builder(String transmitter, BiConsumer<List<String>, Map<String, Object>> onEnd) {
        return new Builder(transmitter, onEnd);
    }

    public Map<String, Object> stream() {
        return stream;
    }

    public void track(Map<String, ?> session) {
        Map<String, Object> previous = index.add(session);
        // Inline, on the caller's thread, never retried. A refusal does not fail sign-in.
        try {
            if (previous != null) subjectGone(previous);
            subjectAdded(session);
        } catch (RuntimeException err) {
            Caught.error(err);
            note("ssf: Add Subject failed: " + err);
        }
    }

    public void untrack(String localId) {
        Map<String, Object> gone = index.take(localId);
        if (gone == null) return;
        try {
            subjectGone(gone);
        } catch (RuntimeException err) {
            Caught.error(err);
            note("ssf: Remove Subject failed: " + err);
        }
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
        rememberPepStream(stream);
        reportPep(pepStream);
        // A stream that names subjects carries only events about them.
        // pep-policies-changed is about the application, so it is named too, and never removed.
        applicationAdded();
        for (Map<String, Object> session : index.live()) subjectAdded(session);
        List<?> delivered = stream.get("events_delivered") instanceof List<?> items ? items : List.of();
        log.info("ssf: polling stream " + stream.get("stream_id") + " at " + delivery.get("endpoint_url") + ", delivering " + delivered.size() + " event type(s)");
        loopThread = new Thread(this::loop, "ssf-poll");
        loopThread.setDaemon(true);
        loopThread.start();
    }

    public void stop() {
        running = false;
        reportPep(EventStream.DOWN);
        Thread thread = loopThread;
        if (thread != null && thread != Thread.currentThread()) {
            thread.interrupt();
            try {
                thread.join(20_000);
            } catch (InterruptedException err) {
                Caught.error(err);
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
                        boolean more = pollNow();
                        reportPep(pepStream);
                        mine.done.complete(more);
                    } catch (Throwable err) {
                        Caught.error(err);
                        reportPep(EventStream.DOWN);
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
            Caught.error(err);
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
                Caught.warn(err);
                log.warn("ssf: poll failed: " + err);
                delay = Math.min(pollIntervalMs * 4, 60_000);
            }
            if (!running) return;
            if (delay <= 0) continue;
            try {
                Thread.sleep(delay);
            } catch (InterruptedException err) {
                Caught.warn(err);
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
                Caught.warn(err);
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
                    Caught.error(err);
                    log.error("ssf: onEndSessions threw for " + eventType + " (SET " + jti + " is still acknowledged): " + err);
                    event.put("ended", false);
                }
                if (event.get("ended") == Boolean.TRUE) {
                    for (String localId : sessions) {
                        Map<String, Object> gone = index.take(localId);
                        if (gone != null) subjectGone(gone);
                    }
                }
            }
            List<Consumer<Map<String, Object>>> called = new ArrayList<>();
            if (handlers.get(eventType) != null) called.addAll(handlers.get(eventType));
            if (handlers.get("*") != null) called.addAll(handlers.get("*"));
            for (Consumer<Map<String, Object>> handler : called) {
                try {
                    handler.accept(event);
                } catch (Exception err) {
                    Caught.error(err);
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
                    return withRequestedEvents(candidate, endpoint);
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

    /**
     * A reused stream can predate an event type this receiver asks for now.
     * PATCH merges the missing types in. A refusal is reported and the
     * receiver still starts.
     */
    private Map<String, Object> withRequestedEvents(Map<String, Object> stream, String endpoint) {
        List<String> requested = stringsOrNull(stream.get("events_requested"));
        if (requested == null) requested = stringsOrNull(stream.get("events_delivered"));
        if (requested == null) return stream;
        List<String> missing = new ArrayList<>();
        for (String event : eventsRequested) if (!requested.contains(event)) missing.add(event);
        if (missing.isEmpty()) return stream;
        List<String> merged = new ArrayList<>(requested);
        merged.addAll(missing);
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("stream_id", stream.get("stream_id"));
        body.put("events_requested", merged);
        try {
            Answer updated = call("PATCH", endpoint, body);
            Map<String, Object> parsed = map(updated.json);
            if (updated.status == 200 && parsed != null && String.valueOf(stream.get("stream_id")).equals(String.valueOf(parsed.get("stream_id")))) {
                if (parsed.get("delivery") == null && stream.get("delivery") != null) parsed.put("delivery", stream.get("delivery"));
                return parsed;
            }
            note("ssf: adding " + String.join(", ", missing) + " to stream " + stream.get("stream_id") + " answered " + updated.status + ": " + clip(updated.json));
        } catch (RuntimeException err) {
            Caught.error(err);
            note("ssf: adding " + String.join(", ", missing) + " to stream " + stream.get("stream_id") + " failed: " + err);
        }
        return stream;
    }

    private void rememberPepStream(Map<String, Object> stream) {
        if (pepWantingEvents(relyingParty) == null) return;
        Boolean delivered = containsEvent(stream.get("events_delivered"));
        Boolean requested = containsEvent(stream.get("events_requested"));
        boolean carried = delivered != null ? delivered : requested == null || requested;
        pepStream = carried ? EventStream.REQUESTED : EventStream.EXCLUDED;
    }

    private Boolean containsEvent(Object list) {
        if (!(list instanceof List<?> items)) return null;
        for (Object item : items) if (Pep.POLICIES_CHANGED_EVENT.equals(String.valueOf(item))) return true;
        return false;
    }

    private void reportPep(EventStream state) {
        Pep pep = pepWantingEvents(relyingParty);
        if (pep == null || state == null) return;
        try {
            pep.setEventStream(state);
        } catch (RuntimeException err) {
            Caught.error(err);
            note("ssf: reporting the PEP's stream failed: " + err);
        }
    }

    private static Pep pepWantingEvents(RelyingParty party) {
        if (party == null || party.pep() == null || !PepWiring.wantsEvents(party.pep())) return null;
        return party.pep();
    }

    private static boolean subjectsConfiguredOff(RelyingParty party) {
        if (party == null) return false;
        Map<String, Object> ssf = Jsons.map(party.config().get("ssf"));
        return ssf != null && ssf.get("addSubjects") == Boolean.FALSE;
    }

    private void applicationAdded() {
        Pep pep = pepWantingEvents(relyingParty);
        if (!addSubjects || pep == null) return;
        String application = pep.config().application;
        if (application == null || application.isEmpty()) return;
        Map<String, Object> subject = new LinkedHashMap<>();
        subject.put("format", "opaque");
        subject.put("id", application);
        String[] where = subjectEndpoint("add_subject_endpoint");
        if (where == null) return;
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("stream_id", where[1]);
        body.put("subject", subject);
        body.put("verified", true);
        subjectCall(where[0], body, "Add Subject (opaque) for the application on stream " + where[1]);
    }

    private void subjectAdded(Map<String, ?> session) {
        if (!addSubjects) return;
        synchronized (added) {
            subjectAddedHeld(session);
        }
    }

    private void subjectAddedHeld(Map<String, ?> session) {
        String[] where = subjectEndpoint("add_subject_endpoint");
        if (where == null) return;
        Map<String, Object> subject = subjectOfSession(session);
        if (subject == null) return;
        String key = Jsons.write(subject);
        if (added.contains(key)) return;
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("stream_id", where[1]);
        body.put("subject", subject);
        // The person comes from an ID token this library verified.
        body.put("verified", true);
        String format = String.valueOf(subject.get("format"));
        if (subjectCall(where[0], body, "Add Subject (" + format + ") for a signed-in person on stream " + where[1])) {
            added.add(key);
        }
    }

    private void subjectGone(Map<String, ?> session) {
        if (!addSubjects) return;
        synchronized (added) {
            subjectGoneHeld(session);
        }
    }

    private void subjectGoneHeld(Map<String, ?> session) {
        Map<String, Object> subject = subjectOfSession(session);
        if (subject == null) return;
        String key = Jsons.write(subject);
        if (!added.contains(key)) return;
        for (Map<String, Object> other : index.live()) {
            Map<String, Object> still = subjectOfSession(other);
            if (still != null && key.equals(Jsons.write(still))) return;
        }
        String[] where = subjectEndpoint("remove_subject_endpoint");
        if (where == null) return;
        if (!added.remove(key)) return;
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("stream_id", where[1]);
        body.put("subject", subject);
        String format = String.valueOf(subject.get("format"));
        subjectCall(where[0], body, "Remove Subject (" + format + ") for a signed-out person on stream " + where[1]);
    }

    /** The endpoint and the stream id, while the receiver runs and both are known. */
    private String[] subjectEndpoint(String name) {
        if (!running || config == null || stream == null) return null;
        Object endpoint = config.get(name);
        Object streamId = stream.get("stream_id");
        if (!(endpoint instanceof String url) || url.isEmpty() || !text(streamId)) return null;
        return new String[] {url, String.valueOf(streamId)};
    }

    /**
     * {@code iss_sub} with the transmitter's issuer when the person is known,
     * else {@code email}. Null before the transmitter's configuration is known.
     */
    private Map<String, Object> subjectOfSession(Map<String, ?> session) {
        String issuer = config == null || config.get("issuer") == null ? "" : String.valueOf(config.get("issuer"));
        Object person = session.get("person");
        if (person instanceof String sub && !sub.isEmpty()) {
            if (issuer.isEmpty()) return null;
            Map<String, Object> subject = new LinkedHashMap<>();
            subject.put("format", "iss_sub");
            subject.put("iss", issuer);
            subject.put("sub", sub);
            return subject;
        }
        Object email = session.get("email");
        if (email instanceof String text && !text.isEmpty()) {
            Map<String, Object> subject = new LinkedHashMap<>();
            subject.put("format", "email");
            subject.put("email", text.toLowerCase());
            return subject;
        }
        return null;
    }

    /** One subject call. A refusal goes to {@code onError} and never fails sign-in. */
    private boolean subjectCall(String endpoint, Map<String, Object> body, String what) {
        try {
            Answer answer = call("POST", endpoint, body);
            if (answer.status == 200 || answer.status == 201 || answer.status == 204) return true;
            note("ssf: " + what + " answered " + answer.status + ": " + clip(answer.json));
        } catch (RuntimeException err) {
            Caught.error(err);
            note("ssf: " + what + " failed: " + err);
        }
        return false;
    }

    private void note(String line) {
        if (onError != null) {
            try {
                onError.accept(line);
            } catch (RuntimeException err) {
                Caught.error(err);
            }
            return;
        }
        log.warn(line);
    }

    private static List<String> stringsOrNull(Object value) {
        if (!(value instanceof List<?> items)) return null;
        List<String> out = new ArrayList<>();
        for (Object item : items) out.add(String.valueOf(item));
        return out;
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
        Http.Result answer = transport != null
                ? transport.send(method, url, requestHeaders, payload)
                : Http.send(url, method, requestHeaders, payload, tls, "ssf");
        Object parsed = null;
        if (answer.body() != null && !answer.body().isEmpty()) {
            try {
                parsed = Jsons.read(answer.body());
            } catch (IllegalArgumentException err) {
                Caught.error(err);
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
            Caught.error(err);
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

    /**
     * Sends one request to the transmitter. The relying party's
     * {@code transmitterTransport(scope)} is one: it presents a client
     * credentials token, with a DPoP proof when the token is DPoP-bound, and
     * answers a {@code use_dpop_nonce} challenge once.
     */
    @FunctionalInterface
    public interface Transport {
        /**
         * Sends the request.
         *
         * @param method the HTTP method
         * @param url the URL
         * @param headers the request headers ({@code accept}, {@code content-type}, and any the
         *        builder's {@code headers} supplier added)
         * @param body the body, or null
         * @return the answer
         */
        Http.Result send(String method, String url, Map<String, String> headers, byte[] body);
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
        private Transport transport;
        private RelyingParty relyingParty;
        private List<String> eventsRequested;
        private List<String> endOn;
        private MemorySessionIndex index;
        private String description;
        private long pollIntervalMs = 5000;
        private int maxEvents = 50;
        private Log log;
        private Consumer<String> onError;
        private boolean addSubjects = true;

        private Builder(String transmitter, BiConsumer<List<String>, Map<String, Object>> onEnd) {
            this.transmitter = transmitter;
            this.onEnd = onEnd;
        }

        public Builder tls(Map<String, String> tls) { this.tls = tls; return this; }
        public Builder headers(Supplier<Map<String, String>> headers) { this.headers = headers; return this; }

        /**
         * Sends every request to the transmitter through this transport
         * instead of a plain HTTP call. Use the relying party's
         * {@code transmitterTransport(scope)} so DPoP-bound tokens carry
         * proofs.
         *
         * @param transport the transport
         * @return this builder
         */
        public Builder transport(Transport transport) { this.transport = transport; return this; }

        /**
         * The relying party whose PEP this stream serves, and whose
         * configuration's {@code ssf.addSubjects} can turn Add Subject off.
         *
         * @param relyingParty the relying party
         * @return this builder
         */
        public Builder relyingParty(RelyingParty relyingParty) { this.relyingParty = relyingParty; return this; }

        public Builder eventsRequested(List<String> events) { this.eventsRequested = events; return this; }
        public Builder endOn(List<String> events) { this.endOn = events; return this; }
        public Builder sessionIndex(MemorySessionIndex index) { this.index = index; return this; }
        public Builder description(String description) { this.description = description; return this; }
        public Builder pollIntervalMs(long pollIntervalMs) { this.pollIntervalMs = pollIntervalMs; return this; }
        public Builder maxEvents(int maxEvents) { this.maxEvents = maxEvents; return this; }
        public Builder log(Log log) { this.log = log; return this; }

        /**
         * Where a failed subject call or a refused stream update is reported.
         * Unset, it is written with the receiver's log. A sign-in never fails
         * because of either.
         *
         * @param onError the reporter
         * @return this builder
         */
        public Builder onError(Consumer<String> onError) { this.onError = onError; return this; }

        /**
         * Add Subject and Remove Subject (SSF 1.0 sections 8.1.3.2 and
         * 8.1.3.3). Default on. {@code ssf.addSubjects: false} turns it off too.
         *
         * @param addSubjects whether to call them
         * @return this builder
         */
        public Builder addSubjects(boolean addSubjects) { this.addSubjects = addSubjects; return this; }

        public SignalsReceiver build() { return new SignalsReceiver(this); }
    }
}
