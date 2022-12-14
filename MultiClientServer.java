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
        while (true) {
            selector.select();
            var selectedKeys = selector.selectedKeys().iterator();
            while (selectedKeys.hasNext()) {
                SelectionKey key = selectedKeys.next();
                selectedKeys.remove();

                // New Client
                if (key.isAcceptable()) {
                    var client = serverSocket.accept();
                    if (client == null)
                        continue;
                    map.put(client.getRemoteAddress().toString(), new TlsState());
                    map.get(client.getRemoteAddress().toString()).setSide("Server");
                    client.configureBlocking(false);
                    client.register(selector, SelectionKey.OP_READ);
                    System.out.println("New Connection: " + client.getRemoteAddress());
                }

                // Old Client Reading Data
                if (key.isReadable()) {
                    var client = (SocketChannel) key.channel();
                    var remoteAddr = client.getRemoteAddress().toString();
                    try {
                        ByteBuffer b = map.get(remoteAddr).buffer;
                        b.clear();
                        var readBytes = client.read(b);
                        if (readBytes == -1) {
                            continue;
                        }
                        b.flip();
                        map.get(remoteAddr).readResponseBuffer();
                        key.interestOps(SelectionKey.OP_WRITE);
                    } catch (Exception e) {
                        map.remove(remoteAddr);
                        client.close();
                    }
                }

                try {
                    if (key.isWritable()) {
                        var client = (SocketChannel) key.channel();
                        var remoteAddr = client.getRemoteAddress().toString();
                        try {
                            ByteBuffer b = map.get(remoteAddr).buffer;
                            b.clear();
                            map.get(remoteAddr).constructResponseBuffer();
                            client.write(ByteBuffer.wrap(b.array(), 0, map.get(remoteAddr).bufferLength));
                            key.interestOps(SelectionKey.OP_READ);
                        } catch (Exception e) {
                            map.remove(remoteAddr);
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
