package Entities;

import java.io.IOException;
import java.io.DataInputStream;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;

/**
 * Abstraktions einer PrivateKey-Datei-Struktur.
 *
 * Der private Schlüssel soll einer einer Datei <Inhabername>.prv gespeichert werden,
 * deren Struktur wie folgt aussieht:
 * 1. Länge des Inhaber‐Namens (integer)
 * 2. Inhaber‐Name (Bytefolge)
 * 3. Länge des privaten Schlüssels (integer)
 * 4. Privater Schlüssel (Bytefolge) [PKCS8‐Format]
 */
public class PrivateKeyFile extends KeyFile {
    private final PrivateKey key;

    public PrivateKeyFile(String inhaberName, PrivateKey key) {
        super(inhaberName);
        this.key = key;
    }

    public PrivateKeyFile(DataInputStream stream)
        throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        super(stream);

        int keyLength = stream.readInt();
        byte[] keyBytes = new byte[keyLength];

        stream.read(keyBytes);
        KeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        key = keyFactory.generatePrivate(keySpec);

        if (stream.available() > 0)
            throw new IOException("Datei hat zuviel Daten."
                + "Nicht alle bytes konnten interpretiert werden");
    }

    @Override public PrivateKey getKey() {
        return key;
    }
}
