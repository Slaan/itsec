package kerberos;

/* Simulation einer Kerberos-Session mit Zugriff auf einen Fileserver
 /* Client-Klasse
 */


import static java.lang.Thread.sleep;

public class Client extends Object {

  private KDC myKDC; // Konstruktor-Parameter

  private String currentUser; // Speicherung bei Login nötig
  private Ticket tgsTicket = null; // Speicherung bei Login nötig
  private long tgsSessionKey; // K(C,TGS) // Speicherung bei Login nötig

  // Konstruktor
  public Client(KDC kdc) {
    myKDC = kdc;
  }

  public boolean login(String userName, char[] password) {
    boolean result = false;
    currentUser = userName;
    TicketResponse ticketResponse = myKDC.requestTGSTicket(userName, "myTGS", generateNonce());
    if (ticketResponse.decrypt(generateSimpleKeyFromPassword(password))) {
      System.out.println("Ticket decrypted!");
      result = true;
    } else {
      System.out.println("Couldnt decrypt TicketResponse!");
    }
    tgsTicket = ticketResponse.getResponseTicket();
    tgsSessionKey = ticketResponse.getSessionKey();
    System.out.println("ticketResponse: " + ticketResponse);
    return result;
  }

  public boolean showFile(Server fileServer, String filePath) {
    Auth auth = new Auth(currentUser, System.currentTimeMillis());
    auth.encrypt(tgsSessionKey);
    long nonce2 = generateNonce();
    TicketResponse ticketResponse =
        myKDC.requestServerTicket(tgsTicket, auth, fileServer.getName(), nonce2);
    ticketResponse.decrypt(tgsSessionKey);
    if (!(ticketResponse.getNonce() == nonce2)) {
      System.err.println("Client Information: Wrong nonce returned!");
      return false;
    }
    try {
      sleep(1000);
    } catch (InterruptedException e) {
      e.printStackTrace();
    }
    long keyClientServer = ticketResponse.getSessionKey();
    Ticket ticket = ticketResponse.getResponseTicket();
    Auth authClientServer = new Auth(currentUser, System.currentTimeMillis());
    authClientServer.encrypt(keyClientServer);
    fileServer.requestService(ticket, authClientServer, "showFile", filePath);
    return true;
  }

	/* *********** Hilfsmethoden **************************** */

  private long generateSimpleKeyFromPassword(char[] passwd) {
    // Liefert einen eindeutig aus dem Passwort abgeleiteten Schlüssel
    // zurück, hier simuliert als long-Wert
    long pwKey = 0;
    if (passwd != null) {
      for (int i = 0; i < passwd.length; i++) {
        pwKey = pwKey + passwd[i];
      }
    }
    return pwKey;
  }

  private long generateNonce() {
    // Liefert einen neuen Zufallswert
    long rand = (long) (100000000 * Math.random());
    return rand;
  }
}
