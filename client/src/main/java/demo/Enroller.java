package demo;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.ConnectException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Map;

/**
 * Gets an identity from the mock CA over plain HTTP.
 * Demo shortcut (see the spec): the CA cert is trusted from this same unauthenticated call,
 * and the CA hands back the private key. A real client would send a CSR and pin the CA out of band.
 */
public final class Enroller {
    private static final ObjectMapper JSON = new ObjectMapper();

    private Enroller() {}

    /**
     * POSTs /enroll and returns the identity. Retries up to 20 x 250ms on connection errors only
     * (the CA may still be starting); any non-200 reply throws.
     */
    public static Identity enroll(String caUrl, String name, String kind, String issuer) throws Exception {
        String body = JSON.writeValueAsString(Map.of(
                "name", name, "kind", kind, "dns", new String[0], "issuer", issuer));
        HttpRequest req = HttpRequest.newBuilder(URI.create(caUrl + "/enroll"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body)).build();
        HttpClient http = HttpClient.newHttpClient();
        for (int attempt = 1; ; attempt++) {
            try {
                HttpResponse<String> r = http.send(req, HttpResponse.BodyHandlers.ofString());
                if (r.statusCode() != 200) {
                    throw new IllegalStateException("enroll " + name + " failed: " + r.statusCode() + " " + r.body());
                }
                JsonNode n = JSON.readTree(r.body());
                return new Identity(n.get("cert_pem").asText(), n.get("key_pem").asText(), n.get("ca_pem").asText());
            } catch (ConnectException e) {
                if (attempt >= 20) {
                    throw new IllegalStateException("CA not reachable at " + caUrl + " after 20 tries", e);
                }
                Thread.sleep(250);
            }
        }
    }
}
