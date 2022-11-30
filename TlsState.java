import java.security.*;
import java.util.Random;

public class TlsState extends X25519 {
    private byte[] sessionId = new byte[32];

    TlsState() throws NoSuchAlgorithmException {
        super();
        new Random().nextBytes(sessionId);
    }

    public byte[] getSessionId() {
        return this.sessionId;
    }
}
