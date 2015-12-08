import java.io.*;

/**
 * Created by octavian on 23.11.15.
 */
public class Main {
    public static void main(String[] args) throws IOException {new Main(args);}

    DES[] des;
    byte[] initVektor;

    private Main(String[] args) throws IOException {
        // Precondition check. Wow.
        if (args.length != 4)
            throw new RuntimeException("Es wurden nicht 4 argumente uebergeben.");

        InputStream inFile = new FileInputStream(args[0]);
        OutputStream outFile = new FileOutputStream(args[2]);
        initKey(args[1]);

        // What shall we do
        // with the drunken sailor?
        switch (args[3].toLowerCase()) {
            case "encrypt": tripleDesCfb(inFile, outFile, Mode.ENCRYPT); break;
            case "decrypt": tripleDesCfb(inFile, outFile, Mode.DECRYPT); break;
            default:
                System.err.println("Argument 4 gibt es nicht: " + args[3]);
        }
    }

    /**
     * This function will encrypt or decrypt the Stream you provided as inFile and outFile.
     * @param inFile We will read the data from this stream ...
     * @param outFile ... encrypt/decrypt it and write it to this file.
     * @param mode And you can choose wether to encrypt the inFile-Content or to decrypt it.
     * @throws IOException The file broke.
     */
    void tripleDesCfb(InputStream inFile, OutputStream outFile, Mode mode) throws IOException {
        System.out.println("Running " + mode.toString());
        int len;
        byte[] buffer = new byte[8];

        // Set C_0 to IV.
        byte[] cipher = initVektor.clone();

        while ((len = inFile.read(buffer)) > 0) {
            // Tribble that DES (don't allow klingons!)
            if (mode == Mode.DECRYPT) {
                des[0].encrypt(cipher, 0, cipher, 0);
                des[1].decrypt(cipher, 0, cipher, 0);
                des[2].encrypt(cipher, 0, cipher, 0);
            } else {
                des[0].decrypt(cipher, 0, cipher, 0);
                des[1].encrypt(cipher, 0, cipher, 0);
                des[2].decrypt(cipher, 0, cipher, 0);
            }

            // Now do the "magic" CFB does.
            byte[] out = XOR(cipher, buffer);

            // Grab C_n,
            if (mode == Mode.DECRYPT) {
                // C_n is the same as we read from inFile.
                cipher = buffer.clone();
            } else {
                // C_n is the same as we will write to outFile.
                cipher = out;
            }

            outFile.write(out, 0, len);
        }
    }

    /**
     * XOR implementation for byte arrays.
     * Both arrays have to be 8 byte long.
     */
    byte[] XOR(byte[] a, byte[] b) {
        // Precondition checks, Boehm would be proud.
        if (a.length != 8)
            throw new RuntimeException("a.length != 8");
        if (b.length != 8)
            throw new RuntimeException("b.length != 8");
        byte[] c = new byte[8];
        // ^ <-- this is not the power-sign, this is XOR in java. Do not ask me why.
        // use XOR on each byte.
        for (int i = 0; i < 8; i++) {
            c[i] = (byte) (a[i] ^ b[i]);
        }
        return c;
    }

    /**
     * Initialises the values found in the key-file (initialVektor and DES-keys)
     * @param keyfile Path to the keyfile in format 3x(8 byte DES-Key), (8 byte initialVektor)
     * @throws IOException The file broke.
     */
    void initKey(String keyfile) throws IOException {
        BufferedInputStream key = null;
        // Open key file.
        try {
            key = new BufferedInputStream(new FileInputStream(keyfile));
        } catch (FileNotFoundException e) {
            System.err.println("Keyfile not found.");
            e.printStackTrace();
            System.exit(-1);
        }
        // Create 3 DES objects with their keys.
        des = new DES[3];
        for (int i = 0; i < 3; i++) {
            // Read the key
            byte desKey[] = new byte[8];
            key.read(desKey, 0, 8);
            // Create the DES
            des[i] = new DES(desKey);
        }
        // Read the initial vektor.
        initVektor = new byte[8];
        key.read(initVektor, 0, 8);
        // Check that the key-file is empty.
        if (key.available() != 0)
            throw new RuntimeException("Keyfile contains unread bytes.");
        key.close();
    }

    enum Mode {
        ENCRYPT, DECRYPT
    }
}
