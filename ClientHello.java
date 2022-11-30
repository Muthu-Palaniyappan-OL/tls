public class ClientHello {
    private byte majorVersion = 3;
    private byte minorVersion = 3;

    byte[] getBytes() {
        return new byte[] { majorVersion, minorVersion };
    }
}
