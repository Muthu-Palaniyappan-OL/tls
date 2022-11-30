import java.util.Arrays;

public class Main {
  public static void main(String[] args) throws Exception {
    TlsState t = new TlsState();
    System.out.println(Arrays.toString(t.getSessionId()));
    TlsState t1 = new TlsState();
    System.out.println(Arrays.toString(t1.getSessionId()));

    var muthuTlsState = new X25519();
    var kumaranTlsState = new X25519();
    kumaranTlsState.deriveSharedKey(muthuTlsState.getPublicKey());
    muthuTlsState.deriveSharedKey(kumaranTlsState.getPublicKey());

    byte[] mainData = "Muthu".getBytes();
    System.out.println("Original Data: " + Arrays.toString(mainData));

    byte[] encryptedData = muthuTlsState.encrypt(mainData);
    System.out.println("Encrypted Data: " + Arrays.toString(encryptedData));

    byte[] decryptData = kumaranTlsState.decrypt(encryptedData);

    System.out.println("Decrypted Data: " + Arrays.toString(decryptData));
  }
}