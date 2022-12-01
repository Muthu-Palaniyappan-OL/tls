import java.net.*;
import java.nio.*;
import java.nio.channels.*;
import java.util.*;

public class MultiClientServer {
    private static final int PORT = 8080;
    private static HashMap<String, TlsState> map = new HashMap<>();

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
                    map.put(client.getRemoteAddress().toString(), new TlsState());
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
                        ByteBuffer b = map.get(client.getRemoteAddress().toString()).buf;
                        var readBytes = client.read(b);
                        if (readBytes == -1) {
                            continue;
                        }
                        map.get(client.getRemoteAddress().toString()).constructResponseBuffer();
                        key.interestOps(SelectionKey.OP_WRITE);
                    } catch (Exception e) {
                        map.remove(client.getRemoteAddress().toString());
                        client.close();
                    }
                }

                try {
                    if (key.isWritable()) {
                        var client = (SocketChannel) key.channel();
                        if (client == null)
                            continue;
                        try {
                            ByteBuffer b = map.get(client.getRemoteAddress().toString()).buf;
                            client.write(b);
                            key.interestOps(SelectionKey.OP_READ);
                            b.clear();
                        } catch (Exception e) {
                            map.remove(client.getRemoteAddress().toString());
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
