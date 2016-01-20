package kerberos;

/* Simulation einer Kerberos-Session mit Zugriff auf einen Fileserver
 /* KDC-Klasse
 */

import java.util.*;

public class KDC extends Object {

  private final long TEN_HOURS_IN_MILLIS = 36000000; // 10 Stunden in
  // Millisekunden

  private final long FIVE_MINUTES_IN_MILLIS = 300000; // 5 Minuten in
  // Millisekunden

	/* *********** Datenbank-Simulation **************************** */

  private String tgsName;

  private String user; // C

  private long userPasswordKey; // K(C)

  private String serverName; // S

  private long serverKey; // K(S)

  //private long serverSessionKey; // K(C,S)

  //private long tgsSessionKey; // K(C,TGS)

  private long tgsKey; // K(TGS)

  // Konstruktor
  public KDC(String name) {
    tgsName = name;
    // Eigenen Key f�r TGS erzeugen (streng geheim!!!)
    tgsKey = generateSimpleKey();
  }

  public String getName() {
    return tgsName;
  }

	/* *********** Initialisierungs-Methoden **************************** */

  public long serverRegistration(String sName) {
    /*
		 * Server in der Datenbank registrieren. R�ckgabe: ein neuer geheimer
		 * Schl�ssel f�r den Server
		 */
    serverName = sName;
    // Eigenen Key f�r Server erzeugen (streng geheim!!!)
    serverKey = generateSimpleKey();
    return serverKey;
  }

  public void userRegistration(String userName, char[] password) {
		/* User registrieren --> Eintrag des Usernamens in die Benutzerdatenbank */
    user = userName;
    userPasswordKey = generateSimpleKeyForPassword(password);

    System.out.println("Principal: " + user);
    System.out.println("Password-Key: " + userPasswordKey);
  }

	/* *********** AS-Modul: TGS - Ticketanfrage **************************** */

  public TicketResponse requestTGSTicket(String userName, String tgsServerName, long nonce) {
		/* Anforderung eines TGS-Tickets bearbeiten. R�ckgabe: TicketResponse f�r die Anfrage */

    TicketResponse tgsTicketResp = null;
    Ticket tgsTicket = null;
    long currentTime = 0;

    // TGS-Antwort zusammenbauen
    if (userName.equals(user) && // Usernamen und Userpasswort in der
        // Datenbank suchen!
        tgsServerName.equals(tgsName)) {
      // OK, neuen Session Key f�r Client und TGS generieren
      long tgsSessionKey = generateSimpleKey();
      currentTime = (new Date()).getTime(); // Anzahl mSek. seit
      // 1.1.1970

      // Zuerst TGS-Ticket basteln ...
      tgsTicket =
          new Ticket(user, tgsName, currentTime, currentTime + TEN_HOURS_IN_MILLIS, tgsSessionKey);

      // ... dann verschl�sseln ...
      tgsTicket.encrypt(tgsKey);

      // ... dann Antwort erzeugen
      tgsTicketResp = new TicketResponse(tgsSessionKey, nonce, tgsTicket);

      // ... und verschl�sseln
      tgsTicketResp.encrypt(userPasswordKey);
    }
    return tgsTicketResp;
  }

	/*
	 * *********** TGS-Modul: Server - Ticketanfrage
	 * ****************************
	 */

  /**
   * Anforderung eines Server-Tickets bearbeiten.
   * @return TicketResponse für die Anfrage
   */
  public TicketResponse requestServerTicket(Ticket tgsTicket, Auth tgsAuth, String serverName,
      long nonce) {
    if (!tgsTicket.decrypt(tgsKey)) {
      throw new RuntimeException("KDC: Could not decrypt tgsTicket.");
    }
    long tgsSessionKey = tgsTicket.getSessionKey();
    if (!tgsAuth.decrypt(tgsSessionKey)) {
      throw new RuntimeException("KDC: Could not decrypt tgsAuth.");
    }
    // Check for authentification
    if (!tgsTicket.getClientName().equals(tgsAuth.getClientName())) {
      System.err.println(
          "KDC Information: Authentification failed!\n" + "tgsTicket Name: " + "" + tgsTicket
              .getClientName() + "\n" + "Auth Client Name: " + tgsAuth.getClientName());
      return new TicketResponse(1, 1, new Ticket("", "", 1, 1, 1));
    }
    // Check for expiration
    if (!(tgsTicket.getStartTime() < System.currentTimeMillis()
        && System.currentTimeMillis() < tgsTicket.getEndTime())) {
      System.err.println("KDC Information: Ticket invalid due to expiration");
    }
    // Generate Session key for client-server communication
    long serverSessionKey = generateSimpleKey();
    // generate ticket for server
    Ticket ticketForServer =
        new Ticket(tgsTicket.getClientName(), serverName, System.currentTimeMillis(),
            System.currentTimeMillis() + TEN_HOURS_IN_MILLIS, serverSessionKey);
    ticketForServer.encrypt(serverKey);
    TicketResponse ticketResponse = new TicketResponse(serverSessionKey, nonce, ticketForServer);
    ticketResponse.encrypt(tgsSessionKey);
    return ticketResponse;
  }

	/* *********** Hilfsmethoden **************************** */

  private long getServerKey(String sName) {
    // Liefert den zugeh�rigen Serverkey f�r den Servernamen zur�ck
    // Wenn der Servername nicht bekannt, wird -1 zur�ckgegeben
    if (sName.equalsIgnoreCase(serverName)) {
      System.out.println("Serverkey ok");
      return serverKey;
    } else {
      System.out.println("Serverkey unbekannt!!!!");
      return -1;
    }
  }

  private long generateSimpleKeyForPassword(char[] pw) {
    // Liefert einen Schl�ssel f�r ein Passwort zur�ck, hier simuliert als
    // long-Wert
    long pwKey = 0;
    for (int i = 0; i < pw.length; i++) {
      pwKey = pwKey + pw[i];
    }
    return pwKey;
  }

  private long generateSimpleKey() {
    // Liefert einen neuen geheimen Schl�ssel, hier nur simuliert als
    // long-Wert
    long sKey = (long) (100000000 * Math.random());
    return sKey;
  }

  boolean timeValid(long lowerBound, long upperBound) {
    long currentTime = (new Date()).getTime(); // Anzahl mSek. seit
    // 1.1.1970
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
    // Wenn die �bergebene Zeit nicht mehr als 5 Minuten von der aktuellen
    // Zeit abweicht,
    // wird true zur�ckgegeben
    long currentTime = (new Date()).getTime(); // Anzahl mSek. seit
    // 1.1.1970
    if (Math.abs(currentTime - testTime) < FIVE_MINUTES_IN_MILLIS) {
      return true;
    } else {
      System.out.println(
          "-------- Time not fresh: " + currentTime + " is current, " + testTime + " is old!");
      return false;
    }
  }
}
