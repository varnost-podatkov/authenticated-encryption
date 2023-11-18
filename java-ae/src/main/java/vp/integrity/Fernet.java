package vp.integrity;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.util.Arrays;
import java.util.Base64;

public class Fernet {

    public static String genKey() throws NoSuchAlgorithmException {
        final byte[] key = new byte[32];
        SecureRandom.getInstanceStrong().nextBytes(key);
        return Base64.getUrlEncoder().encodeToString(key);
    }

    public static byte[] decrypt(String key, String ct) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        // unpack keys
        final byte[] decodedKey = Base64.getUrlDecoder().decode(key);
        final byte[] macKeyBytes = Arrays.copyOfRange(decodedKey, 0, 16);
        final byte[] encKeyBytes = Arrays.copyOfRange(decodedKey, 16, 32);

        // create keys
        final Key macKey = new SecretKeySpec(macKeyBytes, "HmacSHA256");
        final Key encKey = new SecretKeySpec(encKeyBytes, "AES");

        // load ciphertext into bytebuffer
        final byte[] decodedCt = Base64.getUrlDecoder().decode(ct);
        final ByteBuffer buff = ByteBuffer.wrap(decodedCt);

        // check version
        final int version = buff.get() & 0xff;
        assert version == 128;

        // check timestamp
        final long timestamp = buff.getLong();
        System.out.println(new java.util.Date(timestamp * 1000));

        // get IV
        final byte[] iv = new byte[16];
        buff.get(iv, 0, 16);

        // get ct
        final byte[] ctBytes = new byte[buff.remaining() - 32];
        buff.get(ctBytes, 0, ctBytes.length);

        // mac tag
        final byte[] tag = new byte[32];
        buff.get(tag, 0, 32);

        // check MAC
        final Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(macKey);
        final byte[] recomputedTag = mac.doFinal(buff.slice(0, decodedCt.length - 32).array());
        assert MessageDigest.isEqual(tag, recomputedTag);

        // decrypt
        final Cipher aes = Cipher.getInstance("AES/CBC/PKCS5Padding");
        aes.init(Cipher.DECRYPT_MODE, encKey, new IvParameterSpec(iv));
        return aes.doFinal(ctBytes);
    }

    public static void main(String[] args) throws Exception {
        final String key = Files.readString(Path.of("../data/fernet.key"));
        final String ct = Files.readString(Path.of("../data/fernet.ct"));

        System.out.println(new String(decrypt(key, ct), StandardCharsets.UTF_8));
    }
}
