import java.net.*;
import java.nio.channels.*;
import java.nio.*;

public class Main {
  public static void main(String[] args) throws Exception {
    var sock = SocketChannel.open();
    sock.connect(new InetSocketAddress("localhost", 8080));

    var t = new TlsState();
    t.buffer.clear();
    var size = t.constructResponseBuffer();
    sock.write(ByteBuffer.wrap(t.buffer.array(), 0, size));
    t.buffer.clear();
    sock.read(t.buffer);
    t.buffer.flip();
    t.readResponseBuffer();
  }
}