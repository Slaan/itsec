/* MD.java */

import java.io.*;
import java.security.*;

/**
 * In diesem Beispiel wird der Message Digest fuer eine Datei berechnet und
 * angezeigt. Der Algorithmus fuer die kryptographische Hashfunktion (z.B.
 * "SHA-1", "SHA-256" oder "MD5") und der Dateiname werden als Argument von der
 * Kommandozeile gelesen.
 */
public class ShowMD {

	public static void main(String[] args) {
		if (args.length < 2) {
			System.out.println("Usage: java MD md-algorithm filename");
		} else {
			ShowMD myShow = new ShowMD();
			myShow.compute(args[0], args[1]);
		}
	}

	public void compute(String mdAlgorithm, String filename) {
		try {
			// MessageDigest-Objekt erstellen (Algorithmus z.B. SHA-256 oder
			// MD5)
			MessageDigest md = MessageDigest.getInstance(mdAlgorithm);

			// Datei oeffnen
			FileInputStream in = new FileInputStream(filename);
			int len;
			byte[] data = new byte[1024];
			// Datei lesen
			while ((len = in.read(data)) > 0) {
				// MessageDigest mit weiteren Daten versorgen
				md.update(data, 0, len);
			}
			in.close();

			// MessageDigest (kryptogr. Hashwert) berechnen
			byte[] result = md.digest();

			// MessageDigest ausgeben
			System.out.println("\nDer MessageDigest (kryptographische "
					+ md.getAlgorithm() + "-Hashwert) der Datei " + filename
					+ " ist:");
			byteArraytoHexString(result);
		} catch (Exception e) {
			System.err.println(e.toString());
		}
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
}
