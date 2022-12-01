import java.net.*;
import java.nio.*;
import java.nio.channels.*;

public class Main {
  public static void main(String[] args) throws Exception {
    var sock = SocketChannel.open();
    sock.connect(new InetSocketAddress("localhost", 8080));
    ByteBuffer buf = ByteBuffer.allocate(16000);

    buf.put((byte) 127).rewind();
    sock.write(buf);

    buf.flip();

    sock.read(buf);
    buf.rewind();

    System.out.println(buf.get());
  }
}