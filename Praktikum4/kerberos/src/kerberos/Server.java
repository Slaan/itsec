package kerberos;

/* Simulation einer Kerberos-Session mit Zugriff auf einen Fileserver
 /* Server-Klasse
 */

import java.util.*;
import java.io.*;

public class Server extends Object {

  private final long FIVE_MINUTES_IN_MILLIS = 300000; // 5 Minuten in
  // Millisekunden

  private String myName; // Konstruktor-Parameter
  private KDC myKDC; // wird bei KDC-Registrierung gespeichert
  private long myKey; // wird bei KDC-Registrierung gespeichert

  // Konstruktor
  public Server(String name) {
    myName = name;
  }

  public String getName() {
    return myName;
  }

  public void setupService(KDC kdc) {
    // Anmeldung des Servers beim KDC
    myKDC = kdc;
    myKey = myKDC.serverRegistration(myName);
    System.out.println("Server " + myName + " erfolgreich registriert bei KDC " + myKDC.getName()
        + " mit ServerKey " + myKey);
  }

  /**
   * „showFile“-Befehl mit Filepath als Parameter ausführen, d.h. Dateiinhalt zeilenweise
   * auf der Konsole ausgeben.
   * @return Status (Befehlsausführung ok / fehlgeschlagen)
   */
  public boolean requestService(Ticket srvTicket, Auth srvAuth, String command, String parameter) {
    if (!srvTicket.decrypt(myKey)) {
      throw new RuntimeException("Server: Could not decrypt srvTicket.");
    }
    if (!srvAuth.decrypt(srvTicket.getSessionKey())) {
      throw new RuntimeException("Server: Could not decrypt srvAuth.");
    }
    // Ueberpruefung des Tickets.
    if (!srvTicket.getServerName().equals(myName)) {
      System.err.println("Server Information: Wrong Server requested" + srvTicket.getServerName());
      return false;
    }
    if (!(srvTicket.getClientName().equals(srvAuth.getClientName()))) {
      System.err.println("Server Information: Authentification failed! Client name dos not match");
      return false;
    }
    if (!(srvTicket.getStartTime() < System.currentTimeMillis() && srvTicket.getEndTime() > System
        .currentTimeMillis())) {
      System.err.println(
          "Server Information: Ticket not valid due to expiration \n" + "StartTime: " + srvTicket
              .getStartTime() + "\n" + "EndTime: " + srvTicket.getEndTime() + "\n" + "CurrentTime: "
              + System.currentTimeMillis());
      return false;
    }
    // Ausfuehrung des Kommandos.
    if (command.equals("showFile")) {
      showFile(parameter);
    } else {
      System.err.println("Server: requestService: Command " + command + " not found.");
    }
    return true;
  }

	/* *********** Services **************************** */

  private boolean showFile(String filePath) {
    /*
		 * Angegebene Datei auf der Konsole ausgeben. R�ckgabe: Status der
		 * Operation
		 */
    String lineBuf = null;
    File myFile = new File(filePath);
    boolean status = false;

    if (!myFile.exists()) {
      System.out.println("Datei " + filePath + " existiert nicht!");
    } else {
      try {
        // Datei �ffnen und zeilenweise lesen
        BufferedReader inFile =
            new BufferedReader(new InputStreamReader(new FileInputStream(myFile)));
        lineBuf = inFile.readLine();
        while (lineBuf != null) {
          System.out.println(lineBuf);
          lineBuf = inFile.readLine();
        }
        inFile.close();
        status = true;
      } catch (IOException ex) {
        System.out.println("Fehler beim Lesen der Datei " + filePath + ex);
      }
    }
    return status;
  }

	/* *********** Hilfsmethoden **************************** */

  private boolean timeValid(long lowerBound, long upperBound) {
		/*
		 * Wenn die aktuelle Zeit innerhalb der �bergebenen Zeitgrenzen liegt,
		 * wird true zur�ckgegeben
		 */

    long currentTime = (new Date()).getTime(); // Anzahl mSek. seit 1.1.1970
    if (currentTime >= lowerBound && currentTime <= upperBound) {
      return true;
    } else {
      System.out.println(
          "-------- Time not valid: " + currentTime + " not in (" + lowerBound + "," + upperBound
              + ")!");
      return false;
    }
  }

  boolean timeFresh(long testTime) {
		/*
		 * Wenn die �bergebene Zeit nicht mehr als 5 Minuten von der aktuellen
		 * Zeit abweicht, wird true zur�ckgegeben
		 */
    long currentTime = (new Date()).getTime(); // Anzahl mSek. seit 1.1.1970
    if (Math.abs(currentTime - testTime) < FIVE_MINUTES_IN_MILLIS) {
      return true;
    } else {
      System.out.println(
          "-------- Time not fresh: " + currentTime + " is current, " + testTime + " is old!");
      return false;
    }
  }
}
