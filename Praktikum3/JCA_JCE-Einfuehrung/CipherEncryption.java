import java.io.IOException;
import java.security.*;

import javax.crypto.*;
import javax.crypto.spec.*;

/**
 * Dieses Beispiel zeigt die Verwendung der Klasse Cipher zum Verschluesseln von
 * beliebigen Daten.
 */
public class CipherEncryption {

	public static void main(String[] argv) {
		CipherEncryption myTest = new CipherEncryption();
		myTest.performTest();
	}

	public void performTest() {
		try {
			// Geheimen Schluessel (AES) erzeugen
			SecretKey sKey = generateSecretKey();
			// Schluessel in Bytefolge konvertieren
			byte[] secretKeyBytes = sKey.getEncoded();
			System.out.println("Geheimer Schluessel in Hex-Darstellung: ");
			byteArraytoHexString(secretKeyBytes);

			// Cipher- Objekt, welches den Schluessel, Algorithmus und die
			// Parameter beinhaltet, erzeugen
			Cipher cipher = generateCipher(sKey);

			// Cipher-Objekt zur Verschluesselung von Daten verwenden
			byte[] cipherBytes = encryptData("Das ist nur ein Test!!", cipher);
			System.out.println("Verschluesselte Daten: "
					+ new String(cipherBytes));

			// hier findet die Uebertragung der Bytes statt (ist ja nur ein
			// Beispiel) ...

			// Uebertragene Cipher-Bytes, Schluessel-Bytes und Parameter-Bytes zur
			// Entschluesselung der Daten verwenden
			byte[] result = decryptData(cipherBytes, secretKeyBytes, cipher
					.getParameters().getEncoded());
			System.out.println("Entschluesselte Daten: " + new String(result));
		} catch (Exception ex) {
			// ein Fehler???
			System.out.println("Error: " + ex.getMessage());
		}

	}

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

	public Cipher generateCipher(SecretKey skey)
			throws NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidKeyException {
		// Cipher-Objekt erzeugen und initialisieren mit AES-Algorithmus und
		// Parametern (z.B. IV-Erzeugung)
		// SUN-Default ist ECB-Modus (damit kein IV uebergeben werden muss)
		// und PKCS5Padding
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

		// Initialisierung zur Verschluesselung mit automatischer
		// Parametererzeugung
		cipher.init(Cipher.ENCRYPT_MODE, skey);

		// Fertig
		return cipher;
	}

	public byte[] encryptData(String message, Cipher cipher)
			throws IllegalBlockSizeException, BadPaddingException {
		// nun werden die Daten verschluesselt
		// (update wird bei grossen Datenmengen mehrfach aufgerufen werden!)
		byte[] encData = cipher.update(message.getBytes());

		// mit doFinal abschliessen (Rest inkl. Padding ..)
		byte[] encRest = cipher.doFinal();

		byte[] allEncDataBytes = concatenate(encData, encRest);

		// Rueckgabe: die verschluesselten Datenbytes
		return allEncDataBytes;
	}

	public byte[] decryptData(byte[] cipherBytes, byte[] secretKeyBytes,
			byte[] parameterBytes) throws NoSuchAlgorithmException,
			IOException, NoSuchPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException,
			BadPaddingException {
		// Datenbytes entschluesseln

		// Zuerst muss aus der Bytefolge eine neue AES-Schluesselspezifikation
		// erzeugt werden (transparenter Schluessel)
		SecretKeySpec skspec = new SecretKeySpec(secretKeyBytes, "AES");

		// Algorithmische Parameter aus Parameterbytes ermitteln (z.B. IV)
		AlgorithmParameters algorithmParms = AlgorithmParameters
				.getInstance("AES");
		algorithmParms.init(parameterBytes);

		// Cipher-Objekt zur Entschluesselung erzeugen
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

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