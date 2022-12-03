import java.security.*;
import java.security.spec.*;
import java.util.Arrays;

import javax.crypto.*;
import javax.crypto.spec.*;

class X25519 {
    private PrivateKey privateKey;
    private PublicKey publicKey;
    private byte[] privateKeyBytes;
    private byte[] publicKeyBytes;
    private byte[] otherPublicKey;
    private byte[] deriveSharedKey;

    X25519() throws NoSuchAlgorithmException {
        final var kp = KeyPairGenerator.getInstance("X25519").genKeyPair();
        privateKey = kp.getPrivate();
        publicKey = kp.getPublic();
        privateKeyBytes = kp.getPrivate().getEncoded();
        publicKeyBytes = kp.getPublic().getEncoded();
    }

    public byte[] deriveSharedKey()
            throws NoSuchAlgorithmException, InvalidKeyException, IllegalStateException, InvalidKeySpecException {
        var ka = KeyAgreement.getInstance("X25519");
        ka.init(privateKey);
        System.out.println("Others Public Key: " + Arrays.toString(otherPublicKey));
        ka.doPhase(KeyFactory.getInstance("X25519").generatePublic(new X509EncodedKeySpec(otherPublicKey)), true);
        this.deriveSharedKey = ka.generateSecret();
        return this.deriveSharedKey;
    }

    public byte[] getPublicKey() {
        return this.publicKeyBytes;
    }

    public byte[] getPrivateKey() {
        return this.privateKeyBytes;
    }

    public byte[] getOthersPublicKey() {
        return this.otherPublicKey;
    }

    public void setOthersPublicKey(byte[] byt) {
        this.otherPublicKey = byt;
    }

    public byte[] getDerivedKey() {
        return this.deriveSharedKey;
    }

    public byte[] encrypt(byte[] data) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException,
            IllegalBlockSizeException, BadPaddingException {
        if (deriveSharedKey == null)
            return null;
        var secretKeySpec = new SecretKeySpec(deriveSharedKey, "AES");
        var cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
        return cipher.doFinal(data);
    }

    public byte[] decrypt(byte[] data) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
            IllegalBlockSizeException, BadPaddingException {
        if (deriveSharedKey == null)
            return null;
        var secretKeySpec = new SecretKeySpec(deriveSharedKey, "AES");
        var cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
        return cipher.doFinal(data);
    }
}