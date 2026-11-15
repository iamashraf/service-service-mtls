package demo;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

class OrdersGrpcTest {
    @Test
    void enrolledIdentityBuildsAChannelAndAnUnreachableServerIsUnavailable() throws Exception {
        try (FakeCa ca = new FakeCa()) {
            Identity id = Enroller.enroll(ca.url(), "java-writer", "client", "demo", ca.secret);
            try (OrdersGrpc g = new OrdersGrpc(id, "localhost:1", null)) {
                assertEquals(io.grpc.Status.Code.UNAVAILABLE, g.list().code());
            }
        }
    }
}
