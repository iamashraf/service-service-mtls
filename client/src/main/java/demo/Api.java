package demo;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.ConnectException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;

/** Calls the API over mTLS as one identity. */
public final class Api {
    /** Outcome of one call: HTTP status and body, or the exception if the call threw. */
    public record Result(int status, String body, Exception error) {
        /** Returns the server's JSON "error" reason, or null if there is none. */
        public String reason() {
            try {
                JsonNode e = new ObjectMapper().readTree(body).get("error");
                return e == null ? null : e.asText();
            } catch (Exception ex) {
                return null;
            }
        }
    }

    private static final ObjectMapper JSON = new ObjectMapper();
    // Only the very first call of the run retries refused connections (the API may still be starting).
    private static final AtomicBoolean FIRST = new AtomicBoolean(true);

    private final HttpClient http;
    private final String base;

    /** Creates a client for {@code base} (e.g. https://api.demo:8443) using the context's identity. */
    public Api(SSLContext ctx, String base) {
        SSLParameters p = new SSLParameters();
        p.setProtocols(new String[] {"TLSv1.3"}); // TLS 1.3 only
        // Hostname check stays on: HTTPS algorithm is the default and we never override it.
        this.http = HttpClient.newBuilder().sslContext(ctx).sslParameters(p)
                .connectTimeout(Duration.ofSeconds(5)).build();
        this.base = base;
    }

    /** POST /token with no body; returns the raw result. */
    public Result token() {
        return send("POST", "/token", null, null);
    }

    /** Extracts access_token from a successful /token result; throws if missing. */
    public static String accessToken(Result r) throws Exception {
        if (r.error() != null) throw r.error();
        if (r.status() != 200) throw new IllegalStateException("token failed: " + r.status() + " " + r.body());
        String token = JSON.readTree(r.body()).path("access_token").asText("");
        if (token.isEmpty()) throw new IllegalStateException("token response has no access_token: " + r.body());
        return token;
    }

    /** GET /orders with a Bearer token. */
    public Result get(String token) {
        return send("GET", "/orders", token, null);
    }

    /** POST /orders {"item": item} with a Bearer token. */
    public Result post(String token, String item) {
        try {
            return send("POST", "/orders", token, JSON.writeValueAsString(Map.of("item", item)));
        } catch (Exception e) {
            return new Result(-1, "", e);
        }
    }

    /** Sends one request; never throws. Retries ConnectException up to 20 x 250ms on the run's first call only. */
    private Result send(String method, String path, String token, String json) {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(base + path)).timeout(Duration.ofSeconds(5));
        if (token != null) b.header("Authorization", "Bearer " + token);
        if (json != null) b.header("Content-Type", "application/json");
        b.method(method, json == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(json));
        HttpRequest req = b.build();
        int tries = FIRST.getAndSet(false) ? 20 : 1;
        for (int i = 1; ; i++) {
            try {
                HttpResponse<String> r = http.send(req, HttpResponse.BodyHandlers.ofString());
                return new Result(r.statusCode(), r.body(), null);
            } catch (ConnectException e) {
                if (i >= tries) return new Result(-1, "", e);
                try { Thread.sleep(250); } catch (InterruptedException ie) { return new Result(-1, "", ie); }
            } catch (Exception e) {
                return new Result(-1, "", e);
            }
        }
    }
}
