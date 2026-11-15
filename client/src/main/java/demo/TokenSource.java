package demo;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.grpc.CallCredentials;
import io.grpc.Metadata;
import io.grpc.Status;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.Executor;
import java.util.function.Supplier;

/**
 * Gets an access token from the auth server over mTLS and caches it until 30s before it expires.
 *
 * <p>This is deliberately not grpc-auth's STS credentials. That client does its own token request and
 * sends no client certificate (grpc-go issue 5099), so the auth server would never see a cert and the
 * token could not be bound to it. Here the fetch reuses {@link Api}, which has the identity's cert.
 */
public final class TokenSource {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final Duration MARGIN = Duration.ofSeconds(30);
    private static final Metadata.Key<String> AUTHORIZATION =
            Metadata.Key.of("authorization", Metadata.ASCII_STRING_MARSHALLER);

    private final Supplier<Api.Result> fetch;
    private final Clock clock;
    private String token;
    private Instant refreshAt = Instant.MIN;

    /** {@code fetch} makes the /token call (for example {@code api::token}); the clock is injectable for tests. */
    public TokenSource(Supplier<Api.Result> fetch, Clock clock) {
        this.fetch = fetch;
        this.clock = clock;
    }

    /** Returns the cached token, or fetches a new one when none is cached or it is within 30s of expiry. */
    public synchronized String token() throws Exception {
        if (token == null || !clock.instant().isBefore(refreshAt)) {
            Api.Result r = fetch.get();
            String t = Api.accessToken(r);
            JsonNode n = JSON.readTree(r.body());
            token = t;
            refreshAt = clock.instant().plusSeconds(n.path("expires_in").asLong(0)).minus(MARGIN);
        }
        return token;
    }

    /** Call credentials that set {@code authorization: Bearer <token>}; the fetch runs on the call's executor. */
    public CallCredentials credentials() {
        return new CallCredentials() {
            @Override
            public void applyRequestMetadata(RequestInfo info, Executor executor, MetadataApplier applier) {
                executor.execute(() -> {
                    try {
                        Metadata md = new Metadata();
                        md.put(AUTHORIZATION, "Bearer " + token());
                        applier.apply(md);
                    } catch (Exception e) {
                        applier.fail(Status.UNAUTHENTICATED.withDescription("token fetch failed").withCause(e));
                    }
                });
            }
        };
    }
}
