import java.net.*;
import java.nio.*;
import java.nio.channels.*;

public class MultiClientServer {
    private static final int PORT = 8080;

    public static void main(String[] args) throws Exception {
        var selector = Selector.open();
        var serverSocket = ServerSocketChannel.open();
        serverSocket.configureBlocking(false);
        serverSocket.bind(new InetSocketAddress("localhost", PORT));
        serverSocket.register(selector, SelectionKey.OP_ACCEPT);
        var buf = ByteBuffer.allocate(1024);
        while (true) {
            selector.select();
            var selectedKeys = selector.selectedKeys().iterator();
            while (selectedKeys.hasNext()) {
                var key = (SelectionKey) selectedKeys.next();
                selectedKeys.remove();

                // New Client
                if (key.isAcceptable()) {
                    var client = serverSocket.accept();
                    if (client == null)
                        continue;
                    client.configureBlocking(false);
                    client.register(selector, SelectionKey.OP_READ);
                    System.out.println("New Connection: " + client);
                }

                // Old Client Reading Data
                if (key.isReadable()) {
                    var client = (SocketChannel) key.channel();
                    if (client == null)
                        continue;

                    try {
                        buf.clear();
                        var readBytes = client.read(buf);
                        if (readBytes == -1) {
                            System.out.println("Data Over");
                            continue;
                        }
                        key.interestOps(SelectionKey.OP_WRITE);
                    } catch (Exception e) {
                        client.close();
                    }
                }

                try {
                    if (key.isWritable()) {
                        var client = (SocketChannel) key.channel();
                        if (client == null)
                            continue;
                        try {
                            client.write(ByteBuffer.wrap("Muthu\n".getBytes()));
                            key.interestOps(SelectionKey.OP_READ);
                        } catch (Exception e) {
                            client.close();
                        }
                    }
                } catch (Exception e) {
                    key.cancel();
                }

            }
        }
    }
}
