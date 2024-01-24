import java.io.IOException;
import java.math.BigInteger;
import java.io.FileOutputStream;

/**
 * The KeyManager class provides functionalities for generating elliptic curve cryptographic key pairs.
 * @author Andy Comfort
 * @author Caroline El Jazmi
 * @author Brandon Morgan
 */
public class KeyManager {
    private static final BigInteger r = BigInteger.valueOf(2).pow(446).subtract(new BigInteger("13818066809895115352007386748515426880336692474882178609894547503885"));
    
    private static final Ed448Points G = Ed448Points.getPublicGenerator();
    /**
     * Generates an elliptic curve cryptographic key pair based on the Ed448 Goldilocks curve and a passphrase.
     * Writes the public key to the specified output path.
     *
     * @param pw The passphrase used for key generation, as a byte array.
     * @param publicOutputPath The file path where the generated public key should be written.
     * @param privateOutputPath The file path where the generated public key should be written.
     */
    public static void generateKeyPairs(byte[] pw, String publicOutputPath,String privateOutputPath) {
        System.out.println("Generating key pair for Ed448 Goldilocks...");
        byte[] secretBytes = KMACXOF256.getKMACXOF256(pw, "".getBytes(), 448, "SK");
       
        BigInteger s = new BigInteger(1, secretBytes);
        s = s.multiply(BigInteger.valueOf(4)).mod(r);

        byte[] encryptedS = Crypt.encrypt(pw, s.toByteArray());
        writeByteData(privateOutputPath, encryptedS);

        Ed448Points V = Ed448Points.scalarMultiply(G, s);
        writeByteData(publicOutputPath, pointDataZip(V));
    }
    /**
     * Writes a byte array to a file at the specified path.
     *
     * @param path The path where the file should be written.
     * @param theBytes The byte array to be written to the file.
     * @throws IOException If an I/O error occurs during writing.
     */
    public static void writeByteData(final String path, final byte[] theBytes) {
        try (FileOutputStream fos = new FileOutputStream(path)) {
            fos.write(theBytes);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    /**
     * Zips the point data of an Ed448Points object into a byte array.
     * The byte array consists of the length of the x and y coordinates followed by their byte arrays.
     *
     * @param pt The Ed448Points object whose data is to be zipped.
     * @return A byte array representing the zipped point data.
     */
    public static byte[] pointDataZip(final Ed448Points pt) {
        byte[] xBytes = pt.getXBytes();
        byte[] yBytes = pt.getYBytes();

        byte[] xBytesLength = numberToByteArray(xBytes.length);
        byte[] yBytesLength = numberToByteArray(yBytes.length);

        return KMACXOF256.concatByteArr(xBytesLength, yBytesLength, xBytes, yBytes);
    }
    /**
     * Converts an integer to a 4-byte array.
     *
     * @param number The integer to be converted.
     * @return A 4-byte array representing the integer.
     */
    public static byte[] numberToByteArray(int number) {
        return new byte[]{
                (byte)((number >>> 24) & 0xff),
                (byte)((number >>> 16) & 0xff),
                (byte)((number >>> 8) & 0xff),
                (byte)( number & 0xff)
        };
    }


}