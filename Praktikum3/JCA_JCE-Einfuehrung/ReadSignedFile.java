import java.security.*;
import java.security.spec.*;
import java.io.*;

/**
 * In diesem Beispiel wird eine Datei mit einer Nachricht, zugehoeriger
 * SHA-256/RSA-Signatur und oeffentlichem Schluessel im X.509-Format geoeffnet
 * und die Signatur mit Hilfe des oeffentlichen Schluessels verifiziert.
 */

public class ReadSignedFile extends Object {

	// Name der Datei, aus der die signierte Nachricht gelesen wird
	public String fileName;

	// Konstruktor
	public ReadSignedFile(String fileName) {
		this.fileName = fileName;
	}

	public static void main(String args[]) {
		// Name der zu lesenden Signaturdatei = 1. Argument der Kommandozeile
		if (args.length < 1) {
			System.out.println("Usage: java ReadSignedFile filename");
		} else {
			ReadSignedFile rsf = new ReadSignedFile(args[0]);

			// Die Nachricht wird wieder gelesen und die Signatur ueberprueft
			String msg = rsf.readAndVerifyMessage();
			System.out.println("Signierte Nachricht: " + msg);
		}
	}

	/**
	 * Diese Methode liest eine Nachricht, deren Signatur und den gehoerigen
	 * oeffentlichen Schluessel zur Verifizierung der Signatur. Dann wird die
	 * Signatur ueberprueft und die Nachricht zurueckgelierfert.
	 */
	public String readAndVerifyMessage() {

		byte[] messageBytes = null;
		byte[] signatureBytes = null;
		byte[] pubKeyBytes = null;

		try {
			// die Datei wird geoeffnet und die Daten gelesen
			DataInputStream is = new DataInputStream(new FileInputStream(
					fileName));
			// die Laenge der Nachricht
			int len = is.readInt();
			messageBytes = new byte[len];
			// die Nachricht
			is.read(messageBytes);
			// die Laenge der Signatur
			len = is.readInt();
			signatureBytes = new byte[len];
			// die Signatur
			is.read(signatureBytes);
			// die Laenge des oeffentlichen Schluessels
			len = is.readInt();
			pubKeyBytes = new byte[len];
			// der oeffentliche Schluessel
			is.read(pubKeyBytes);
			// Datei schliessen
			is.close();
		} catch (IOException ex) {
			Error("Datei-Fehler beim Lesen der signierten Nachricht!", ex);
		}

		try {
			// aus dem Byte-Array koennen wir eine X.509-Schluesselspezifikation
			// erzeugen
			X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(pubKeyBytes);

			// nun wird aus der Spezifikation wieder abgeschlossener public key
			// erzeugt
			KeyFactory keyFac = KeyFactory.getInstance("RSA");
			PublicKey pubKey = keyFac.generatePublic(x509KeySpec);

			// Nun wird die Signatur ueberprueft
			// als Erstes erzeugen wir das Signatur-Objekt
			Signature rsaSig = Signature.getInstance("SHA256withRSA");
			// zum Verifizieren benoetigen wir den oeffentlichen Schluessel
			rsaSig.initVerify(pubKey);
			// Daten fuer die kryptographische Hashfunktion (hier: SHA-256)
			// liefern
			rsaSig.update(messageBytes);

			// Signatur verifizieren:
			// 1. Verschluesselung der Signatur (mit oeffentlichem
			// RSA-Schluessel)
			// 2. Vergleich des Ergebnisses mit dem kryptogr. Hashwert
			boolean ok = rsaSig.verify(signatureBytes);
			if (ok)
				System.out.println("Signatur erfolgreich verifiziert!");
			else
				System.out.println("Signatur konnte nicht verifiziert werden!");

		} catch (NoSuchAlgorithmException ex) {
			Error("Es existiert keine Implementierung fuer RSA.", ex);
		} catch (InvalidKeySpecException ex) {
			Error("Fehler beim Konvertieren des Schluessels.", ex);
		} catch (SignatureException ex) {
			Error("Fehler beim ueberpruefen der Signatur!", ex);
		} catch (InvalidKeyException ex) {
			Error("Falscher Algorithmus?", ex);
		}

		// als Ergebnis liefern wir die urpspruengliche Nachricht
		return new String(messageBytes);
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
	private void Error(String msg, Exception ex) {
		System.out.println(msg);
		System.out.println(ex.getMessage());
		System.exit(0);
	}

}
