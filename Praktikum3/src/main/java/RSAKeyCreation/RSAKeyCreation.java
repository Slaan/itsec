package RSAKeyCreation;

import Entities.KeyFile;
import Entities.PrivateKeyFile;
import Entities.PublicKeyFile;

import java.io.*;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

/**
 * welches ein RSA‐Schlüsselpaar erzeugt
 * (Schlüssellänge: 2048 Bit) und beide Schlüssel jeweils in einer Datei speichert.
 *
 * Beispiel: java RSAKeyCreation KMueller
 * erzeugt die Ausgabedateien KMueller.pub  und  KMueller.prv
 */
public class RSAKeyCreation {


    public static void main(String[] args) {
        if (args.length != 1)
            throw new RuntimeException("Ein Argument erwartet: java -jar RSAKeyCreation.jar <Inhaber>");
        RSAKeyCreation rsaKeyCreation = new RSAKeyCreation(args[0]);
        rsaKeyCreation.generateKeyPair();

        File pub = new File(args[0] + ".pub");
        File prv = new File(args[0] + ".prv");
        try {
            // Speichere Public-Key.
            DataOutputStream pubOut = new DataOutputStream(new FileOutputStream(pub));
            rsaKeyCreation.savePublicKey(pubOut);
            pubOut.close();

            // Speichere Private-Key
            DataOutputStream prvOut = new DataOutputStream(new FileOutputStream(prv));
            rsaKeyCreation.savePrivateKey(prvOut);
            prvOut.close();
        } catch (IOException e) {
            // Im Fehlerfall werden beide Dateien als ungueltig angesehen.
            pub.delete();
            prv.delete();
            throw new RuntimeException("Datei operations Fehler.", e);
        }
    }

    public RSAKeyCreation(String inhaberName) {
        this.inhaberName = inhaberName;
    }

    // das Schluesselpaar
    private KeyPair keyPair = null;
    private String inhaberName;

    /**
     * Diese Methode generiert ein neues Schluesselpaar.
     */
    public void generateKeyPair() {
        try {
            // als Algorithmus verwenden wir RSA
            KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
            // mit gewuenschter Schluessellaenge initialisieren
            gen.initialize(2048);
            keyPair = gen.generateKeyPair();
        } catch (NoSuchAlgorithmException ex) {
            throw new RuntimeException("Es existiert kein KeyPairGenerator fuer RSA", ex);
        }
    }

    /**
     * Speichern des PublicKeys.
     * @param stream Stream in den der PublicKey geschrieben werden soll.
     */
    public void savePublicKey(DataOutputStream stream) throws IOException {
        KeyFile key = new PublicKeyFile(inhaberName, keyPair.getPublic());
        key.saveToStream(stream);
    }

    /**
     * Speichern des PrivateKeys.
     * @param stream Stream in den der PrivateKey geschrieben werden soll.
     */
    public void savePrivateKey(DataOutputStream stream) throws IOException {
        KeyFile key = new PrivateKeyFile(inhaberName, keyPair.getPrivate());
        key.saveToStream(stream);
    }
}
