package Entities;

import sun.security.x509.X509Key;

import java.io.IOException;
import java.io.DataInputStream;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * Abstraktions einer PublicKey-Datei-Struktur.
 *
 * Der öffentliche Schlüssel soll einer einer Datei <Inhabername>.pub gespeichert werden,
 * deren Struktur wie folgt aussieht:
 * 1. Länge des Inhaber‐Namens (integer)
 * 2. Inhaber‐Name (Bytefolge)
 * 3. Länge des öffentlichen Schlüssels (integer)
 * 4. Öffentlicher Schlüssel (Bytefolge) [X.509‐Format]
 */
public class PublicKeyFile extends KeyFile {
    private final PublicKey key;

    public PublicKeyFile(String inhaberName, PublicKey key) {
        super(inhaberName);
        this.key = key;
    }
    public PublicKeyFile(DataInputStream stream)
        throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        super(stream);

        int keyLength = stream.readInt();
        byte[] keyBytes = new byte[keyLength];

        stream.read(keyBytes);
        KeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        key = keyFactory.generatePublic(keySpec);

        if (stream.available() > 0)
            throw new IOException("Datei hat zuviel Daten."
                + "Nicht alle bytes konnten interpretiert werden");
    }

    @Override public PublicKey getKey() {
        return key;
    }

}
