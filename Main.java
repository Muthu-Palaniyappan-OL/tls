import java.net.*;
import java.nio.channels.*;
import java.nio.*;

public class Main {
  public static void main(String[] args) throws Exception {
    var sock = SocketChannel.open();
    sock.connect(new InetSocketAddress("localhost", 8080));

    var t = new TlsState();
    t.buffer.clear();

    int size = t.recordHeader(t.buffer, b2 -> {
      return t.handshakeHeader(b2, b1 -> {
        return t.extensions(b1, b -> {
          return t.tls13version(b);
        }, b -> {
          return t.keyShare(b);
        });
      });
    });

    // t.printBuffer(size);
    System.out.println(size);
    sock.write(ByteBuffer.wrap(t.buffer.array(), 0, size));

    t.buffer.clear();
    sock.read(t.buffer);

    t.buffer.flip();

    System.out.println(t.buffer.get());
  }
}