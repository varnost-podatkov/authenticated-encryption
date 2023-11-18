package vp.integrity;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.MessageDigest;
import java.util.HexFormat;

public class GCMExample {
    public static void main(String[] args) throws Exception {
        // Ustvarimo sporočilo in ga postrojimo z UTF8
        final String message = "Moje sporočilo.";
        final byte[] pt = message.getBytes(StandardCharsets.UTF_8);

        // Ustvarimo naključen ključ
        final Key key = KeyGenerator.getInstance("AES").generateKey();

        // Ustvarimo algoritem MAC
        final Cipher ana = Cipher.getInstance("AES/GCM/NoPadding");
        // In mu podamo ključ
        ana.init(Cipher.ENCRYPT_MODE, key);
        final byte[] ct = ana.doFinal(pt);
        final byte[] iv = ana.getIV();

        System.out.printf("Poslala sem: '%s'%n", message);

        // Šestnajstiški izpis izračunane značke
        System.out.println("PT: " + HexFormat.of().formatHex(pt));
        System.out.println("CT: " + HexFormat.of().formatHex(ct));

        // Simuliramo, da Ana pošlje par (pt, tag) Boru

        // Bor prav tako ustvari enak algoritem MAC
        final Cipher bor = Cipher.getInstance("AES/GCM/NoPadding");
        ana.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, iv));
        final byte[] dt = ana.doFinal(ct);
        System.out.println("DT: " + HexFormat.of().formatHex(dt));
        // Če se ujemata, izpišemo sporočil (a še prej ga moremo dekodirati v UTF8 niz)
        System.out.printf("Prejel sem: '%s'%n", new String(dt, StandardCharsets.UTF_8));
    }
}
