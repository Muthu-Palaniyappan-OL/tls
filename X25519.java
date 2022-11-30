import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;

public class X25519 {
    private KeyPair kp;
    private byte[] othersPubKey;
    private byte[] publicKey;
    private byte[] deriveSharedKey;

    X25519() throws NoSuchAlgorithmException {
        kp = KeyPairGenerator.getInstance("X25519").generateKeyPair();
        this.publicKey = kp.getPublic().getEncoded();
    }

    public void deriveSharedKey(byte[] othersPublicKey)
            throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException {
        this.othersPubKey = othersPublicKey;
        final var kf = KeyFactory.getInstance("X25519");
        final var keyspec = new X509EncodedKeySpec(othersPublicKey);
        var othersPubKey = kf.generatePublic(keyspec);
        var ka = KeyAgreement.getInstance("X25519");
        ka.init(kp.getPrivate());
        ka.doPhase(othersPubKey, true);
        this.deriveSharedKey = ka.generateSecret();
    }

    public byte[] getPublicKey() {
        return this.publicKey;
    }

    public byte[] getOthersPublicKey() {
        return this.othersPubKey;
    }

    public byte[] encrypt(byte[] data) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException,
            IllegalBlockSizeException, BadPaddingException {
        var secretKeySpec = new SecretKeySpec(deriveSharedKey, "AES");
        var cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
        return cipher.doFinal(data);
    }

    public byte[] decrypt(byte[] data) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
            IllegalBlockSizeException, BadPaddingException {
        var secretKeySpec = new SecretKeySpec(deriveSharedKey, "AES");
        var cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
        return cipher.doFinal(data);
    }
}