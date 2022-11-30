import java.net.*;
import java.nio.*;
import java.nio.channels.*;

public class MultiClientServer {
    public static void main(String[] args) throws Exception {
        var selector = Selector.open();
        var serverSocket = ServerSocketChannel.open();
        serverSocket.bind(new InetSocketAddress("localhost", 8080));
        serverSocket.configureBlocking(false);
        serverSocket.register(selector, SelectionKey.OP_ACCEPT);
        var buf = ByteBuffer.allocate(1024);
        while (true) {
            selector.select();
            var selectedKeys = selector.selectedKeys();
            for (var i : selectedKeys) {
                if (i.isAcceptable()) {
                    var client = serverSocket.accept();
                    client.configureBlocking(false);
                    client.register(selector, SelectionKey.OP_READ);
                }
                if (i.isReadable()) {
                    var client = (SocketChannel) i.channel();
                    client.read(buf);

                    // Main Code

                    System.out.println(buf);
                }
                selectedKeys.remove(i);
            }
        }
    }
}
