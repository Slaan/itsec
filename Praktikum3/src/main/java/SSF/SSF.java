package SSF;

import Entities.KeyFile;
import Entities.PrivateKeyFile;
import Entities.PublicKeyFile;

import java.io.*;
import java.nio.ByteBuffer;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;

/**
 * Erzeugen, Signieren und Verschlüsseln eines geheimen Sitzungsschlüssels und Verschlüsseln
 * einer Dokumentendatei (Sender)
 */
public class SSF {
    private final String AES_ALGORITHMIC_PARAMETER = "AES/CTR/NoPadding";

    // TODO:
    // Ist "CipherEncryption.java" hilfreich?
    /*
      Schreiben Sie ein JAVA‐Programm SSF („SendSecureFile“) mit folgender Funktionalität:
     a) Einlesen eines privaten RSA‐Schlüssels (.prv) aus einer Datei gemäß Aufgabenteil 1.
     b) Einlesen eines öffentlichen RSA‐Schlüssels (.pub) aus einer Datei gemäß Aufgabenteil 1.
     c) Erzeugen eines geheimen Schlüssels für den AES‐Algorithmus mit der Schlüssellänge 128 Bit
     d) Erzeugung einer Signatur für den geheimen Schlüssel aus c) mit dem privaten RSA‐Schlüssel
     (Algorithmus: „SHA256withRSA“)
     e) Verschlüsselung des geheimen Schlüssel aus c) mit dem öffentlichen RSA‐Schlüssel (Algorithmus:
     „RSA“)
     f) Einlesen einer Dokumentendatei, Verschlüsseln der Dateidaten mit dem symmetrischen AES‐
     Algorithmus (geheimer Schlüssel aus c) im Counter‐Mode („CTR“) und Erzeugen einer
     Ausgabedatei.

     Die Ausgabedatei soll folgende Struktur besitzen:
     1. Länge des verschlüsselten geheimen Schlüssels (integer)
     2. Verschlüsselter geheimer Schlüssel (Bytefolge)
     3. Länge der Signatur des geheimen Schlüssels (integer)
     4. Signatur des geheimen Schlüssels (Bytefolge)
     5. Länge der algorithmischen Parameter des geheimen Schlüssels
     6. Algorithmische Parameter des geheimen Schlüssels (Bytefolge)
     7. Verschlüsselte Dateidaten (Ergebnis von f) (Bytefolge)

     Die Dateinamen sollen als Argument in der Kommandozeile übergeben werden.
     Als privater Schlüssel ist derjenige des Senders zu verwenden, als öffentlicher Schlüssel derjenige des
     Empfängers.

     Beispiel (K. Müller sendet an F. Meier):
     java SSF KMueller.prv FMeier.pub Brief.pdf Brief.ssf
     */
    public static void main(String[] args) throws Exception {
        if (args.length != 4)
            throw new RuntimeException("Es muessen 4 Parameter verwendet werden: "
                + "java SSF KMueller.prv FMeier.pub Brief.pdf Brief.ssf");
        new SSF(args);
    }

    public SSF(String[] args) {
        DataOutputStream outputStream = null;
        DataInputStream inputStream = null;
        try {
            outputStream = new DataOutputStream(new FileOutputStream(args[3]));
            inputStream = new DataInputStream(new FileInputStream(args[2]));
        } catch (Exception e) {
            throw new RuntimeException("Konnte Eingabe- oder Ausgabedatei nicht oeffnen.");
        }


        PrivateKeyFile prv = null; // a
        PublicKeyFile pub = null; // b
        try {
            prv = new PrivateKeyFile(new DataInputStream(new FileInputStream(args[0]))); // a
            System.out.println("Success: Read private Key: " + prv.getInhaberName());
            pub = new PublicKeyFile(new DataInputStream(new FileInputStream(args[1]))); // b
            System.out.println("Success: Read public Key: " + pub.getInhaberName());
        } catch (Exception e) {
            throw new RuntimeException("Konnte Privaten- oder Oeffentlichen Schluessel nicht oeffnen.", e);
        }

        try {
            SecretKey aesKey = generateSecretKey(); // c
            // DateiOP: 1 & 2 // e
            Cipher rsaPubCipher = generateCipher(pub.getKey(), "RSA");
            byte[] encryptedAESKey = encryptData(aesKey.getEncoded(), rsaPubCipher);
            outputStream.writeInt(encryptedAESKey.length);
            outputStream.write(encryptedAESKey);

            signAndSaveMessage(new KeyPair(pub.getKey(), prv.getKey()), aesKey.getEncoded(),
                outputStream); // d

            // e
            Cipher aesCipher = generateCipher(aesKey, AES_ALGORITHMIC_PARAMETER);
            byte[] encryptionParameters = aesCipher.getParameters().getEncoded();

            outputStream.writeInt(encryptionParameters.length);
            outputStream.write(encryptionParameters);

            // f:
            byte[] in = new byte[aesCipher.getBlockSize()];
            int lenRead;
            while ((lenRead = inputStream.read(in)) > 0) {
                outputStream.write(aesCipher.update(in, 0, lenRead));
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
    public void signAndSaveMessage(KeyPair keyPair, byte[] messageBytes, DataOutputStream os) {

        // die Nachricht als Byte-Array
        Signature rsaSignature = null;
        byte[] signatureBytes = null;
        try {
            // als Erstes erzeugen wir das Signatur-Objekt
            rsaSignature = Signature.getInstance("SHA256withRSA");
            // zum Signieren benoetigen wir den privaten Schluessel (hier: RSA)
            rsaSignature.initSign(keyPair.getPrivate());
            // Daten fuer die kryptographische Hashfunktion (hier: SHA-256)
            // liefern
            rsaSignature.update(messageBytes);
            // Signaturbytes durch Verschluesselung des Hashwerts (mit privatem
            // RSA-Schluessel) erzeugen
            signatureBytes = rsaSignature.sign();
        } catch (NoSuchAlgorithmException ex) {
            throw new RuntimeException("Keine Implementierung fuer SHA256withRSA!", ex);
        } catch (InvalidKeyException ex) {
            throw new RuntimeException("Falscher Schluessel!", ex);
        } catch (SignatureException ex) {
            throw new RuntimeException("Fehler beim Signieren der Nachricht!", ex);
        }

        // der oeffentliche Schluessel vom Schluesselpaar
        PublicKey pubKey = keyPair.getPublic();
        // wir benoetigen die Bytefolge im Default-Format
        byte[] pubKeyBytes = pubKey.getEncoded();

        try {
            // eine Datei wird erzeugt und danach die Nachricht, die Signatur
            // und der oeffentliche Schluessel darin gespeichert
            os.writeInt(signatureBytes.length);
            os.write(signatureBytes);
        } catch (IOException ex) {
            throw new RuntimeException("Fehler beim Schreiben der signierten Nachricht.", ex);
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
        cipher.init(Cipher.ENCRYPT_MODE, skey);

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
