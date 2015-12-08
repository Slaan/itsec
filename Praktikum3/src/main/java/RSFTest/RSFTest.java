package RSFTest;//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by Fernflower decompiler)
//

import java.io.DataInputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class RSFTest {
    public String privFileName;
    public String pubFileName;
    public String ssfFileName;
    public String docFileName;
    private PrivateKey privKey = null;
    private PublicKey pubKey = null;
    public byte[] encodedSKey = null;
    public byte[] encryptedSKey = null;
    private byte[] signature = null;

    public RSFTest() {
    }

    public static void main(String[] args) {
        if(args.length < 4) {
            System.out.println("Usage: java RSFTest filename.prv filename.pub ssf-filename doc-filename");
            System.exit(0);
        } else {
            RSFTest myRSF = new RSFTest();
            myRSF.privFileName = args[0];
            myRSF.pubFileName = args[1];
            myRSF.ssfFileName = args[2];
            myRSF.docFileName = args[3];
            myRSF.readPrivKey();
            myRSF.readPubKey();
            myRSF.convertSSFFile();
            myRSF.verifySignature();
            System.out.println("RSFTest: Fertig! Herzlichen Glueckwunsch!");
        }

    }

    public void readPrivKey() {
        byte[] privKeyEnc = null;
        byte[] sname = null;

        try {
            DataInputStream keyFac = new DataInputStream(new FileInputStream(this.privFileName));
            int pkcs8KeySpec = keyFac.readInt();
            sname = new byte[pkcs8KeySpec];
            keyFac.read(sname);
            pkcs8KeySpec = keyFac.readInt();
            privKeyEnc = new byte[pkcs8KeySpec];
            keyFac.read(privKeyEnc);
            keyFac.close();
        } catch (IOException var8) {
            this.Error("Fehler beim Lesen des private keys!", var8);
        }

        KeyFactory keyFac1 = null;

        try {
            keyFac1 = KeyFactory.getInstance("RSA");
        } catch (NoSuchAlgorithmException var7) {
            this.Error("Es existiert keine KeyFactory fuer RSA.", var7);
        }

        PKCS8EncodedKeySpec pkcs8KeySpec1 = new PKCS8EncodedKeySpec(privKeyEnc);

        try {
            this.privKey = keyFac1.generatePrivate(pkcs8KeySpec1);
        } catch (InvalidKeySpecException var6) {
            this.Error("Fehler beim Konvertieren des Schluessels.", var6);
        }

        System.out.print("Private key ");
        System.out.println(" fuer <" + new String(sname) + "> wurde erfolgreich gelesen!\n");
    }

    public void readPubKey() {
        byte[] pubKeyEnc = null;
        byte[] sname = null;

        try {
            DataInputStream keyFac = new DataInputStream(new FileInputStream(this.pubFileName));
            int x509KeySpec = keyFac.readInt();
            sname = new byte[x509KeySpec];
            keyFac.read(sname);
            x509KeySpec = keyFac.readInt();
            pubKeyEnc = new byte[x509KeySpec];
            keyFac.read(pubKeyEnc);
            keyFac.close();
        } catch (IOException var8) {
            this.Error("Fehler beim Lesen des public keys!", var8);
        }

        KeyFactory keyFac1 = null;

        try {
            keyFac1 = KeyFactory.getInstance("RSA");
        } catch (NoSuchAlgorithmException var7) {
            this.Error("Es existiert keine KeyFactory fuer RSA.", var7);
        }

        X509EncodedKeySpec x509KeySpec1 = new X509EncodedKeySpec(pubKeyEnc);

        try {
            this.pubKey = keyFac1.generatePublic(x509KeySpec1);
        } catch (InvalidKeySpecException var6) {
            this.Error("Fehler beim Konvertieren des Schluessels.", var6);
        }

        String snameStr = new String(sname);
        System.out.print("Public key ");
        System.out.println(" fuer <" + snameStr + "> wurde erfolgreich gelesen!\n");
    }

    public void convertSSFFile() {
        try {
            DataInputStream ex = new DataInputStream(new FileInputStream(this.ssfFileName));
            int len = ex.readInt();
            this.encryptedSKey = new byte[len];
            ex.read(this.encryptedSKey);
            len = ex.readInt();
            this.signature = new byte[len];
            ex.read(this.signature);
            len = ex.readInt();
            byte[] encodedAP = new byte[len];
            ex.read(encodedAP);
            AlgorithmParameters ap = AlgorithmParameters.getInstance("AES");
            ap.init(encodedAP);
            this.decryptKey();
            Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
            SecretKeySpec skspec = new SecretKeySpec(this.encodedSKey, "AES");
            cipher.init(2, skspec, ap);
            FileOutputStream out = new FileOutputStream(this.docFileName);
            byte[] data = new byte[1024];

            while((len = ex.read(data)) > 0) {
                out.write(cipher.update(data, 0, len));
            }

            out.write(cipher.doFinal());
            ex.close();
            out.close();
        } catch (Exception var9) {
            this.Error("Fehler beim Schreiben der Dokumentendatei oder Lesen der .ssf-Datei!", var9);
        }

    }

    public void decryptKey() {
        try {
            Cipher ex = Cipher.getInstance("RSA");
            ex.init(2, this.privKey);
            this.encodedSKey = ex.doFinal(this.encryptedSKey);
            System.out.print("Der geheime Schluessel: ");
            this.byteArraytoHexString(this.encodedSKey);
            System.out.println(" wurde erfolgreich entschluesselt!\n");
        } catch (NoSuchAlgorithmException var2) {
            this.Error("Keine Implementierung fuer RSA vorhanden!", var2);
        } catch (InvalidKeyException var3) {
            this.Error("Falscher Algorithmus?", var3);
        } catch (Exception var4) {
            this.Error("Fehler bei der Entschluesselung des geheimen Schluessels", var4);
        }

    }

    public void verifySignature() {
        Signature rsa = null;

        try {
            rsa = Signature.getInstance("SHA256withRSA");
            rsa.initVerify(this.pubKey);
            rsa.update(this.encodedSKey);
        } catch (NoSuchAlgorithmException var4) {
            this.Error("Keine Implementierung fuer SHA256withRSA vorhanden!", var4);
        } catch (SignatureException var5) {
            this.Error("Fehler beim Ueberpruefen der Signatur!", var5);
        } catch (InvalidKeyException var6) {
            this.Error("Falscher Schluesseltyp bei Ueberpruefung der Signatur!", var6);
        }

        try {
            boolean ex = rsa.verify(this.signature);
            if(ex) {
                System.out.print("Signatur ");
                System.out.println(" erfolgreich verifiziert!\n");
            } else {
                System.out.print("Signatur ");
                this.byteArraytoHexString(this.signature);
                System.out.println(" konnte nicht verifiziert werden\n!");
            }
        } catch (SignatureException var3) {
            this.Error("Fehler beim Verifizieren der Signatur!", var3);
        }

    }

    private void byteArraytoHexString(byte[] byteArray) {
        for(int i = 0; i < byteArray.length; ++i) {
            System.out.print(this.bytetoHexString(byteArray[i]) + " ");
        }

    }

    private String bytetoHexString(byte b) {
        String ret = Integer.toHexString(b & 255).toUpperCase();
        ret = (ret.length() < 2?"0":"") + ret;
        return ret;
    }

    private void Error(String msg, Exception ex) {
        throw new RuntimeException(msg, ex);
    }
}
