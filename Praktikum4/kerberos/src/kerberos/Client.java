package kerberos;

/* Simulation einer Kerberos-Session mit Zugriff auf einen Fileserver
 /* Client-Klasse
 */


import static java.lang.Thread.sleep;

public class Client extends Object {

  private KDC myKDC; // Konstruktor-Parameter

  private String currentUser; // Speicherung bei Login n�tig
  private Ticket tgsTicket = null; // Speicherung bei Login n�tig
  private long tgsSessionKey; // K(C,TGS) // Speicherung bei Login n�tig

  // Konstruktor
  public Client(KDC kdc) {
    myKDC = kdc;
  }

  /**
   * Aufgabe: TGS-Ticket für den übergebenen Benutzer vom KDC (AS) holen (TGS-Servername:
   * myTGS ) und zusammen mit dem TGS-Sessionkey und dem UserNamen speichern.
   * @return Status (Login ok / fehlgeschlagen)
   */
  public boolean login(String userName, char[] password) {
    boolean result = false;
    currentUser = userName;
    // Abholen und ueberpruefen des Tickets fuer den Ticket-Granting-Service.
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

  /**
   * Aufgabe: Serverticket vom KDC (TGS) holen und „showFile“-Service beim übergebenen
   * Fileserver anfordern.
   * @return Status (Befehlsausführung ok / fehlgeschlagen)
   */
  public boolean showFile(Server fileServer, String filePath) {
    Auth auth = new Auth(currentUser, System.currentTimeMillis());
    auth.encrypt(tgsSessionKey);
    long nonce2 = generateNonce();
    // Holen eines Tickets (vom Ticket-Granting-Service) um auf den FileServer zuzugreifen.
    TicketResponse ticketResponse =
        myKDC.requestServerTicket(tgsTicket, auth, fileServer.getName(), nonce2);
    ticketResponse.decrypt(tgsSessionKey);
    if (!(ticketResponse.getNonce() == nonce2)) {
      System.err.println("Client Information: Wrong nonce returned!");
      return false;
    }
    // Simuliere PC-Last.
    try {
      sleep(1000);
    } catch (InterruptedException e) {
      e.printStackTrace();
    }
    long keyClientServer = ticketResponse.getSessionKey();
    Ticket ticket = ticketResponse.getResponseTicket();
    Auth authClientServer = new Auth(currentUser, System.currentTimeMillis());
    authClientServer.encrypt(keyClientServer);
    // Fordere die Ausfuehrung des Kommandos "showFile" an.
    fileServer.requestService(ticket, authClientServer, "showFile", filePath);
    return true;
  }

	/* *********** Hilfsmethoden **************************** */

  private long generateSimpleKeyFromPassword(char[] passwd) {
    // Liefert einen eindeutig aus dem Passwort abgeleiteten Schl�ssel
    // zur�ck, hier simuliert als long-Wert
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
