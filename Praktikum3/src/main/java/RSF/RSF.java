package RSF;

import Entities.PrivateKeyFile;
import Entities.PublicKeyFile;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.*;

/**
 * Created by octavian on 08.12.15.
 */
public class RSF {
    private final String AES_ALGORITHMIC_PARAMETER = "AES/CTR/NoPadding";

    public static void main(String[] args) throws Exception {
        if (args.length != 4)
            throw new RuntimeException("Es muessen 4 Parameter verwendet werden: "
                + "java SSF FMeier.prv KMueller.pub Brief.ssf Brief.pdf ");
        new RSF(args);
    }

    public RSF(String[] args) {
        DataOutputStream outputStream = null;
        DataInputStream inputStream = null;
        try {
            outputStream = new DataOutputStream(new FileOutputStream(args[3]));
            inputStream = new DataInputStream(new FileInputStream(args[2]));
        } catch (Exception e) {
            throw new RuntimeException("Konnte Eingabe- oder Ausgabedatei nicht oeffnen.");
        }


        PrivateKeyFile prv; // a
        PublicKeyFile pub; // b
        try {
            prv = new PrivateKeyFile(new DataInputStream(new FileInputStream(args[0]))); // a
            System.out.println("Success: Read private Key: " + prv.getInhaberName());
            pub = new PublicKeyFile(new DataInputStream(new FileInputStream(args[1]))); // b
            System.out.println("Success: Read public Key: " + pub.getInhaberName());
        } catch (Exception e) {
            throw new RuntimeException("Konnte Privaten- oder Oeffentlichen Schluessel nicht oeffnen.", e);
        }

        try {
            // DateiOP: 1 & 2 // e
            Cipher rsaPubCipher = generateCipher(pub.getKey(), "RSA");

            int encryptedAESKey_length = inputStream.readInt();
            byte[] encryptedAESKey = new byte[encryptedAESKey_length];
            inputStream.read(encryptedAESKey);
            System.out.println("Erfolg: encrypted Key, mit laenge " + encryptedAESKey_length + " ausgelesen.");

            Cipher rsaPrvCipher = generateCipher(prv.getKey(), "RSA");
            byte[] aesKey = encryptData(encryptedAESKey, rsaPrvCipher);

            int signedKey_length = inputStream.readInt();
            byte[] signedKey = new byte[signedKey_length];
            inputStream.read(signedKey);

            signAndConfirmMessage(pub, aesKey, signedKey); // d

            // e
            int encryptionParameters_length = inputStream.readInt();
            byte[] encryptionParameters = new byte[encryptionParameters_length];
            inputStream.read(encryptionParameters);

            // f:

            // Zuerst muss aus der Bytefolge eine neue AES-Schluesselspezifikation
            // erzeugt werden (transparenter Schluessel)
            SecretKeySpec skspec = new SecretKeySpec(aesKey, "AES");

            // Algorithmische Parameter aus Parameterbytes ermitteln (z.B. IV)
            AlgorithmParameters algorithmParms = AlgorithmParameters
                .getInstance("AES");
            algorithmParms.init(encryptionParameters);

            // Cipher-Objekt zur Entschluesselung erzeugen
            Cipher aesCipher = Cipher.getInstance(AES_ALGORITHMIC_PARAMETER);

            // mit diesem Schluessel wird nun die AES-Chiffre im DECRYPT MODE
            // initialisiert (inkl. AlgorithmParameters fuer den IV)
            aesCipher.init(Cipher.DECRYPT_MODE, skspec, algorithmParms);


            byte[] in = new byte[aesCipher.getBlockSize()];
            int readBytes;
            while ((readBytes = inputStream.read(in)) > 0) {
                outputStream.write(aesCipher.update(in, 0, readBytes));
            }
            outputStream.write(aesCipher.doFinal());
        } catch (Exception e) {
            throw new RuntimeException("Allgemeiner Fehler bei SSF.", e);
        }
        try {
            inputStream.close();
            outputStream.close();
        } catch (IOException e) {
            throw new RuntimeException("Konnte Datei Operationen nicht abschliessen.", e);
        }
    }

    /**
     * Die angegebene Nachricht wird signiert. Anschliessend wird die Signatur in eine Datei
     * gespeichert.
     */
    public void signAndConfirmMessage(PublicKeyFile pub, byte[] messageBytes, byte[] origMessageBytes) {

        // die Nachricht als Byte-Array
        Signature rsaSignature = null;
        byte[] signatureBytes = null;
        try {
            // als Erstes erzeugen wir das Signatur-Objekt
            rsaSignature = Signature.getInstance("SHA256withRSA");
            // zum Verifizieren benoetigen wir den oeffentlichen Schluessel (hier: RSA)
            rsaSignature.initVerify(pub.getKey());
            // Daten fuer die kryptographische Hashfunktion (hier: SHA-256)
            // liefern
            rsaSignature.update(messageBytes);
            // Signaturbytes durch Verschluesselung des Hashwerts (mit oeffentlichen
            // RSA-Schluessel) verifizieren
            if (rsaSignature.verify(origMessageBytes)) {
                System.out.println("Signatur erfolgreich verifiziert. Signiert von " + pub.getInhaberName());
            } else {
                System.out.println("Signatur *NICHT* erfolgreich verifiziert. Signatur kommt *NICHT* von " + pub.getInhaberName());
            }
        } catch (NoSuchAlgorithmException ex) {
            throw new RuntimeException("Keine Implementierung fuer SHA256withRSA!", ex);
        } catch (InvalidKeyException ex) {
            throw new RuntimeException("Falscher Schluessel!", ex);
        } catch (SignatureException ex) {
            throw new RuntimeException("Fehler beim Signieren der Nachricht!", ex);
        }

    }

    // TODO: ab hier: CipherEncryption.java

    public SecretKey generateSecretKey() throws InvalidKeyException,
        NoSuchAlgorithmException {
        // AES-Schluessel generieren
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(128); // Schluessellaenge als Parameter
        SecretKey skey = kg.generateKey();

        // zeige den Algorithmus des Schluessels
        System.out.println("Schluesselalgorithmus: " + skey.getAlgorithm());
        // zeige das Format des Schluessels
        System.out.println("Schluesselformat: " + skey.getFormat());

        // Ergebnis
        return skey;
    }

    public Cipher generateCipher(Key skey, String algorithm)
        throws NoSuchAlgorithmException, NoSuchPaddingException,
        InvalidKeyException {
        // Cipher-Objekt erzeugen und initialisieren mit AES-Algorithmus und
        // Parametern (z.B. IV-Erzeugung)
        // SUN-Default ist ECB-Modus (damit kein IV uebergeben werden muss)
        // und PKCS5Padding
        Cipher cipher = Cipher.getInstance(algorithm);

        // Initialisierung zur Verschluesselung mit automatischer
        // Parametererzeugung
        cipher.init(Cipher.DECRYPT_MODE, skey);

        // Fertig
        return cipher;
    }

    public byte[] encryptData(byte[] message, Cipher cipher)
        throws IllegalBlockSizeException, BadPaddingException {
        // nun werden die Daten verschluesselt
        // (update wird bei grossen Datenmengen mehrfach aufgerufen werden!)
        byte[] encData = cipher.update(message);

        // mit doFinal abschliessen (Rest inkl. Padding ..)
        byte[] encRest = cipher.doFinal();

        byte[] allEncDataBytes = concatenate(encData, encRest);

        // Rueckgabe: die verschluesselten Datenbytes
        return allEncDataBytes;
    }

    public byte[] decryptData(byte[] cipherBytes, byte[] secretKeyBytes,
        byte[] parameterBytes) throws NoSuchAlgorithmException,
        IOException, NoSuchPaddingException, InvalidKeyException,
        InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        // Datenbytes entschluesseln

        // Zuerst muss aus der Bytefolge eine neue AES-Schluesselspezifikation
        // erzeugt werden (transparenter Schluessel)
        SecretKeySpec skspec = new SecretKeySpec(secretKeyBytes, "AES");

        // Algorithmische Parameter aus Parameterbytes ermitteln (z.B. IV)
        AlgorithmParameters algorithmParms = AlgorithmParameters
            .getInstance("AES");
        algorithmParms.init(parameterBytes);

        // Cipher-Objekt zur Entschluesselung erzeugen
        Cipher cipher = Cipher.getInstance(AES_ALGORITHMIC_PARAMETER);

        // mit diesem Schluessel wird nun die AES-Chiffre im DECRYPT MODE
        // initialisiert (inkl. AlgorithmParameters fuer den IV)
        cipher.init(Cipher.DECRYPT_MODE, skspec, algorithmParms);

        // und die Daten entschluesselt
        byte[] decData = cipher.update(cipherBytes);

        // mit doFinal abschliessen (Rest inkl. Padding ..)
        byte[] decRest = cipher.doFinal();

        byte[] allDecDataBytes = concatenate(decData, decRest);

        // Rueckgabe: die entschluesselten Klartextbytes
        return allDecDataBytes;
    }

    /**
     * Concatenate two byte arrays
     */
    private byte[] concatenate(byte[] ba1, byte[] ba2) {
        int len1 = ba1.length;
        int len2 = ba2.length;
        byte[] result = new byte[len1 + len2];

        // Fill with first array
        System.arraycopy(ba1, 0, result, 0, len1);
        // Fill with second array
        System.arraycopy(ba2, 0, result, len1, len2);

        return result;
    }
}
