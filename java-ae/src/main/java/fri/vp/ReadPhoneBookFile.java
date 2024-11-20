package fri.vp;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Key;

public class ReadPhoneBookFile {
    public static void main(String[] args) throws Exception {
        // datoteko morate najprej ustvariti s programom pb.py
        final byte[] data = Files.readAllBytes(Path.of("../data/phonebook.bin"));
    }

    // Definirajte pomožno metodo deriveKey in jo uporabite pri branju
    public static Key deriveKey(String password, byte[] salt, int iterations) throws Exception {
        return null;
    }
}
