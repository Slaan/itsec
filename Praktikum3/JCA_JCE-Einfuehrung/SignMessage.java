import java.security.*;
import java.io.*;

/**
 * In diesem Beispiel wird ein RSA-Schluesselpaar erzeugt, anschliessend eine
 * Nachricht signiert und zusammen mit der Signatur und dem oeffentlichen
 * Schluessel in einer Datei gespeichert.
 */

/*
 * Dateibeschreibung: 1. Laenge der Nachricht 2. Nachrichtenbytes 3. Laenge der
 * Signatur 4. Signaturbytes 5. Laenge des oeff. Schluessels 6. Schluesselbytes
 */

public class SignMessage extends Object {

	// Name der Datei, in der die signierte Nachricht gespeichert wird
	public String fileName;
	// das Schluesselpaar
	private KeyPair keyPair = null;

	// Konstruktor
	public SignMessage(String fileName) {
		this.fileName = fileName;
	}

	public static void main(String args[]) {
		// Name der zu erzeugenden Signaturdatei = 1. Argument der Kommandozeile
		// Zu signierende Nachricht = 2. Argument der Kommandozeile
		if (args.length < 2) {
			System.out
					.println("Usage: java SignMessage outFilename messageString");
		} else {
			SignMessage sm = new SignMessage(args[0]);
			// als erstes wird ein neues Schluesselpaar erzeugt
			sm.generateKeyPair();
			// eine Nachricht wird signiert und gespeichert
			sm.signAndSaveMessage(args[1]);
		}
	}

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
			showErrorAndExit("Es existiert kein KeyPairGenerator fuer RSA", ex);
		}
	}

	/**
	 * Die angegebene Nachricht wird signiert und dann zusammen mit der Signatur
	 * und dem oeffentlichen Schluessel (X.509-Format) in eine Datei
	 * gespeichert.
	 */
	public void signAndSaveMessage(String message) {

		// die Nachricht als Byte-Array
		byte[] messageBytes = message.getBytes();
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
			showErrorAndExit("Keine Implementierung fuer SHA256withRSA!", ex);
		} catch (InvalidKeyException ex) {
			showErrorAndExit("Falscher Schluessel!", ex);
		} catch (SignatureException ex) {
			showErrorAndExit("Fehler beim Signieren der Nachricht!", ex);
		}

		// der oeffentliche Schluessel vom Schluesselpaar
		PublicKey pubKey = keyPair.getPublic();
		// wir benoetigen die Bytefolge im Default-Format
		byte[] pubKeyBytes = pubKey.getEncoded();

		try {
			// eine Datei wird erzeugt und danach die Nachricht, die Signatur
			// und der oeffentliche Schluessel darin gespeichert
			DataOutputStream os = new DataOutputStream(new FileOutputStream(
					fileName));
			os.writeInt(messageBytes.length);
			os.write(messageBytes);
			os.writeInt(signatureBytes.length);
			os.write(signatureBytes);
			os.writeInt(pubKeyBytes.length);
			os.write(pubKeyBytes);
			os.close();
		} catch (IOException ex) {
			showErrorAndExit("Fehler beim Schreiben der signierten Nachricht.",
					ex);
		}
		// Bildschirmausgabe
		System.out
				.println("Der Public Key wird in folgendem Format gespeichert: "
						+ pubKey.getFormat());
		byteArraytoHexString(pubKeyBytes);
		System.out.println();
		System.out.println("Erzeugte SHA-256/RSA-Signatur: ");
		byteArraytoHexString(signatureBytes);
	}

	/**
	 * Konvertiert ein Byte-Array in einen Hex-String.
	 */

	private void byteArraytoHexString(byte[] byteArray) {
		for (int i = 0; i < byteArray.length; ++i) {
			System.out.print(bytetoHexString(byteArray[i]) + " ");
		}
		System.out.println();
	}

	private String bytetoHexString(byte b) {
		// --> obere 3 Byte auf Null setzen und zu String konvertieren
		String ret = Integer.toHexString(b & 0xFF).toUpperCase();
		// ggf. fuehrende Null einfuegen
		ret = (ret.length() < 2 ? "0" : "") + ret;
		return ret;
	}

	/**
	 * Diese Methode gibt eine Fehlermeldung sowie eine Beschreibung der
	 * Ausnahme aus. Danach wird das Programm beendet.
	 *
	 * @param msg
	 *            eine Beschreibung fuer den Fehler
	 * @param ex
	 *            die Ausnahme, die den Fehler ausgeloest hat
	 */
	private void showErrorAndExit(String msg, Exception ex) {
		System.out.println(msg);
		System.out.println(ex.getMessage());
		System.exit(0);
	}

}
