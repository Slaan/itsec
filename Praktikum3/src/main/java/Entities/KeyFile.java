package Entities;

import java.io.IOException;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.security.Key;
import java.security.KeyFactory;
import java.security.spec.KeySpec;

/**
 * Abstraktions einer Key-Datei-Struktur.
 */
public abstract class KeyFile {
    private final String inhaberName;

    public KeyFile(String inhaberName) {
        this.inhaberName = inhaberName;
    }
    public KeyFile(DataInputStream stream) throws IOException {
        int inhaberNameLength = stream.readInt();
        byte[] inhaberNameBytes = new byte[inhaberNameLength];
        stream.read(inhaberNameBytes);

        inhaberName = new String(inhaberNameBytes);
    }

    public String getInhaberName() {
        return inhaberName;
    }

    public abstract Key getKey();

    /**
     * Diese Methode schreibt den Key in den uebergebenen stream.
     *
     * Der Schlüssel soll in einer Datei gespeichert werden,
     * deren Struktur wie folgt aussieht:
     * 1. Länge des Inhaber‐Namens (integer)
     * 2. Inhaber‐Name (Bytefolge)
     * 3. Länge des Schlüssels (integer)
     * 4. Schlüssel (Bytefolge) [Formatierung muss bei Aufruf stimmen]
     *
     * @param stream in den der PrivateKey geschrieben wird.
     */
    public void saveToStream(DataOutputStream stream) throws IOException {
        stream.writeInt(inhaberName.length());
        stream.write(inhaberName.getBytes());

        byte[] key = getKey().getEncoded();
        stream.writeInt(key.length);
        stream.write(key);
    }
}
