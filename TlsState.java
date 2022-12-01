import java.nio.ByteBuffer;
import java.security.*;

public class TlsState extends X25519 {
    private byte[] sessionId = null;
    int majorVersion = 0x03;
    int minorVersion = 0x03;
    ByteBuffer buf = ByteBuffer.allocate(16000);

    TlsState() throws NoSuchAlgorithmException {
        super();
    }

    public byte[] getSessionId() {
        return this.sessionId;
    }

    public void constructResponseBuffer() {
        // Read Buffer
        // buf

        // Flipping Buffer
        buf.flip();

        // Construct Response in same Buffer
    }
}
