package demo;

import io.grpc.ManagedChannel;
import io.grpc.Metadata;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import io.grpc.netty.shaded.io.grpc.netty.GrpcSslContexts;
import io.grpc.netty.shaded.io.grpc.netty.NettyChannelBuilder;
import io.grpc.stub.MetadataUtils;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;

/** Calls the Orders gRPC service over mTLS (TLS 1.3 only) as one identity. */
public final class OrdersGrpc implements AutoCloseable {
    /** Outcome of one call: the gRPC status code and message. */
    public record Result(Status.Code code, String message) {
        /** {@code CODE message}, or just {@code CODE} when the message is empty. */
        public String text() {
            return code + (message == null || message.isEmpty() ? "" : " " + message);
        }
    }

    private final ManagedChannel channel;
    private final TokenSource tokens;

    /**
     * Opens a channel that presents the identity's cert and trusts only its CA.
     * With {@code tokens} set, every call carries a Bearer token; with null the calls carry none.
     */
    public OrdersGrpc(Identity id, String target, TokenSource tokens) throws Exception {
        var ssl = GrpcSslContexts.forClient()
                .protocols("TLSv1.3")
                .keyManager(pem(id.certPem()), pem(id.keyPem()))
                .trustManager(pem(id.caPem()))
                .build();
        this.channel = NettyChannelBuilder.forTarget(target).sslContext(ssl).build();
        this.tokens = tokens;
    }

    /** Calls List with the token source's token. */
    public Result list() {
        return call(null, true, null);
    }

    /** Calls Add with the token source's token. */
    public Result add(String item) {
        return call(null, false, item);
    }

    /** Calls List with an explicit token in a plain {@code authorization} header (replay test). */
    public Result listWithToken(String token) {
        return call(token, true, null);
    }

    private Result call(String token, boolean list, String item) {
        var stub = demo.orders.OrdersGrpc.newBlockingStub(channel).withDeadlineAfter(10, TimeUnit.SECONDS);
        if (tokens != null) stub = stub.withCallCredentials(tokens.credentials());
        if (token != null) {
            Metadata md = new Metadata();
            md.put(Metadata.Key.of("authorization", Metadata.ASCII_STRING_MARSHALLER), "Bearer " + token);
            stub = stub.withInterceptors(MetadataUtils.newAttachHeadersInterceptor(md));
        }
        try {
            if (list) stub.list(demo.orders.OrdersOuterClass.ListRequest.getDefaultInstance());
            else stub.add(demo.orders.OrdersOuterClass.AddRequest.newBuilder().setItem(item).build());
            return new Result(Status.Code.OK, "");
        } catch (StatusRuntimeException e) {
            return new Result(e.getStatus().getCode(), e.getStatus().getDescription());
        }
    }

    @Override
    public void close() throws InterruptedException {
        channel.shutdownNow().awaitTermination(2, TimeUnit.SECONDS);
    }

    private static ByteArrayInputStream pem(String s) {
        return new ByteArrayInputStream(s.getBytes(StandardCharsets.US_ASCII));
    }
}
