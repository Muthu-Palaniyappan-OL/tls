import java.nio.ByteBuffer;
import java.security.*;
import java.util.Random;
import java.util.function.Function;

public class TlsState extends X25519 {
    private byte[] sessionId = new byte[32];
    private byte[] random = new byte[32];
    ByteBuffer buffer = ByteBuffer.allocate(16000);
    int bufferLength = 0;
    X25519 crypt = new X25519();

    TlsState() throws NoSuchAlgorithmException {
        super();
        new Random().nextBytes(sessionId);
        new Random().nextBytes(random);
    }

    public byte[] getSessionId() {
        return this.sessionId;
    }

    public void constructResponseBuffer(int bufferLength) {
        // Read Buffer
        // buf

        // Clear Buffer
        // buf.clear();

        // Construct Response in same Buffer

        // this.bufferLength = generateClientHello();
        this.buffer.rewind();
    }

    public void printBuffer(int size) {
        for (int i = 0; i < size; i++) {
            System.out.printf("0x%x ", this.buffer.get(i));
        }
    }

    public int generateClientHello() {
        buffer.clear();
        int len = 0;

        buffer.put((byte) 0x16);
        len += 1;
        buffer.putShort((short) 0x0301);
        len += 2;
        buffer.putShort((short) 0x00f8);
        len += 2;

        buffer.putShort((short) 0x0100);
        len += 2;
        buffer.putShort((short) 0x00f4);
        len += 2;
        buffer.putShort((short) 0x0303);
        len += 2;

        byte[] b = new byte[32];
        new Random().nextBytes(b);
        buffer.put(ByteBuffer.wrap(b));
        len += 32;

        // session id length
        buffer.put((byte) 0x20);
        len += 1;
        buffer.put(ByteBuffer.wrap(this.sessionId));
        len += 32;

        // cipher protocols
        buffer.putShort((short) 0x0002);
        len += 2;
        buffer.putShort((short) 0x1302);
        len += 2;

        // compression method
        buffer.putShort((short) 0x0100);
        len += 2;

        buffer.putShort((short) 0x0000);
        len += 2;

        // updating length record
        buffer.putShort(3, (short) len);
        // updating length handshake header
        buffer.putShort(7, (short) (len - 4));

        buffer.rewind();
        return len;
    }

    public int recordHeader(ByteBuffer buf, Function<ByteBuffer, Integer> header) {
        int len = 0;
        buf.put((byte) 0x16);
        len += 1;
        buf.putShort((short) 0x0301);
        len += 2;
        int pos = buf.position();
        buf.putShort((short) 0x0000);
        int headerLen = header.apply(buf);
        buf.putShort(pos, (short) (len - 3 + headerLen));
        return len + headerLen;
    }

    public int tls13version(ByteBuffer buf) {
        int len = 0;
        buf.putShort((short) 0x002b);
        len += 2;
        buf.putShort((short) 0x0003);
        len += 2;
        buf.put((byte) 0x02);
        len += 1;
        buf.putShort((short) 0x0304);
        len += 2;
        return len;
    }

    public int handshakeHeader(ByteBuffer buf, Function<ByteBuffer, Integer> header) {
        int len = 0;
        buf.putShort((short) 0x0100);
        len += 2;
        int pos = buf.position();
        buf.putShort((short) 0x0000);
        len += 2;
        buf.putShort((short) 0x0303);
        len += 2;
        buf.put(random);
        len += 32;
        buf.put((byte) 0x20);
        len += 1;
        buf.put(sessionId);
        len += 32;
        buf.putShort((short) 0x0002);
        len += 2;
        buf.putShort((short) 0x1302);
        len += 2;
        buf.putShort((short) 0x0100);
        len += 2;

        int headerLength = header.apply(buf);
        buf.putShort(pos, (short) (len + headerLength - 4));
        return len + headerLength;
    }

    public int keyShare(ByteBuffer buf) {
        int publicKeyLen = crypt.getPublicKey().length;
        int len = 0;
        buf.putShort((short) 0x0033);
        len += 2;
        buf.putShort((short) (publicKeyLen + 6));
        len += 2;
        buf.putShort((short) (publicKeyLen + 4));
        len += 2;
        buf.putShort((short) 0x001d);
        len += 2;
        buf.putShort((short) (publicKeyLen));
        len += 2;
        buf.put(crypt.getPublicKey());
        return len + publicKeyLen;
    }

    @SafeVarargs
    public final int extensions(ByteBuffer buf, Function<ByteBuffer, Integer>... ex) {
        int pos = buf.position();
        buf.putShort((short) 0x0000);
        int extensionLen = 0;
        for (int i = 0; i < ex.length; i++) {
            extensionLen += ex[i].apply(buf);
        }
        buf.putShort(pos, (short) extensionLen);
        return extensionLen + 2;
    }
}
