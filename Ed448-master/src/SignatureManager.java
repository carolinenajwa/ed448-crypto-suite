import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Scanner;
/**
 * The SignatureManager class provides functionalities to create and verify signatures using Ed448 elliptic curve cryptography.
 *
 * @author Andy Comfort
 * @author Caroline El Jazmi
 * @author Brandon Morgan
 */
public class SignatureManager {

    private static final BigInteger R = BigInteger.valueOf(2).pow(446).subtract(new BigInteger("13818066809895115352007386748515426880336692474882178609894547503885"));
    private static final Ed448Points PUBLIC_GENERATOR = Ed448Points.getPublicGenerator();
    /**
     * Creates a digital signature for a given message and private key, and writes the signature to the specified output path.
     *
     * @param m The message to be signed, as a byte array.
     * @param pw The private key for signing, as a byte array.
     * @param outputPath The file path where the signature should be written.
     */
    public static void createFileSignature(byte[] m, byte[] pw, String outputPath) {
        // s <- KMACXOF256(pw, “”, 448, “SK”); s <- 4s (mod r)
        byte[] secretBytes = KMACXOF256.getKMACXOF256(pw, "".getBytes(), 448, "SK");
        BigInteger secretBigInt = new BigInteger(1, secretBytes);
        BigInteger s = secretBigInt.multiply(BigInteger.valueOf(4)).mod(R);

        // k <- KMACXOF256(s, m, 448, “N”); k <- 4k (mod r)
        byte[] kBytes = KMACXOF256.getKMACXOF256(s.toByteArray(), m, 448, "N");
        BigInteger kBigInt = new BigInteger(1, kBytes);
        BigInteger k = kBigInt.multiply(BigInteger.valueOf(4)).mod(R);

        // U <- k * G
        Ed448Points U = Ed448Points.scalarMultiply(PUBLIC_GENERATOR, k);

        // h <- KMACXOF256(Ux, m, 448, “T”)
        byte[] hBytes = KMACXOF256.getKMACXOF256(U.getX().toByteArray(), m, 448, "T");
        BigInteger h = new BigInteger(1, hBytes);
        
        // z <- (k – hs) mod r
        BigInteger pre_z = k.subtract(h.multiply(s));
        BigInteger z = pre_z.mod(R);

        byte[] zBytes = z.toByteArray();
        
        // signature: (h, z)
        byte[] signature = KMACXOF256.concatByteArr(zBytes, hBytes);
        
        System.out.println("Signature Saved To: " + outputPath);
        writeByteData(outputPath, signature);
    }
    /**
     * Verifies a digital signature against a given message and public key.
     * Prints the result of the verification process.
     *
     * @param msgBytes The message that was signed, as a byte array.
     * @param sigBytes The signature to be verified, as a byte array.
     * @param pubKeyBytes The public key used for verification, as a byte array.
     */
    public static void verifySignature(byte[] msgBytes, byte[] sigBytes, byte[] pubKeyBytes) {
        Ed448Points pubKey = unzipData(pubKeyBytes);
        
        if (pubKey == null) {
            System.out.println("Public key not found or invalid.");
            return;
        }

        final int zLen = 56;
        byte[] zBytes = Arrays.copyOfRange(sigBytes, 0, zLen);
        byte[] hBytes = Arrays.copyOfRange(sigBytes, zLen, sigBytes.length);

        BigInteger z = new BigInteger(1, zBytes);
        BigInteger h = new BigInteger(1, hBytes);

        Ed448Points Gz = Ed448Points.scalarMultiply(PUBLIC_GENERATOR, z);
        Ed448Points Vh = Ed448Points.scalarMultiply(pubKey, h);
        Ed448Points U = Ed448Points.summation(Gz, Vh);
        
        BigInteger hashPrime = new BigInteger(1, KMACXOF256.getKMACXOF256(U.getXBytes(), msgBytes, 448, "T"));
        
        if (h.equals(hashPrime))
            System.out.println("Signature Verification Successful");
        else System.out.println("Signature Verification Fail!");
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
     * Unzips a byte array representing an Ed448Point into its corresponding object.
     *
     * @param pointData The byte array representing the Ed448Point.
     * @return The Ed448Point object or null if the unzipping fails.
     */
    public static Ed448Points unzipData(byte[] pointData) {
        try {
            int[] lengths = readZipped(pointData);
            int xLen = lengths[0], yLen = lengths[1];

            int xBytesStart = 8;
            int yBytesStart = xBytesStart + xLen;
            int theEnd = yBytesStart + yLen;

            byte[] xBytes = Arrays.copyOfRange(pointData, xBytesStart, yBytesStart);
            byte[] yBytes = Arrays.copyOfRange(pointData, yBytesStart, theEnd);

            return new Ed448Points(new BigInteger(xBytes),new BigInteger(yBytes));
        } catch(Exception e) { return null;}
    }
    /**
     * Reads and converts a specific portion of a byte array into an integer array.
     * Used for processing zipped data.
     *
     * @param pointData The byte array containing the data to be converted.
     * @return An integer array representing the lengths of the zipped data.
     * @throws ArrayIndexOutOfBoundsException If the byte array does not contain the expected data.
     */
    public static int[] readZipped(byte[] pointData) throws ArrayIndexOutOfBoundsException {
        byte[] xByteLength = Arrays.copyOfRange(pointData, 0, 4);
        byte[] yByteLength = Arrays.copyOfRange(pointData, 4, 8);
        return new int[] {bytesToInt(xByteLength), bytesToInt(yByteLength)};
    }
    /**
     * Converts a 4-byte array into an integer.
     *
     * @param theBytes A byte array of length 4 to be converted.
     * @return The integer value represented by the byte array.
     */
    public static int bytesToInt(byte[] theBytes) {
        if (theBytes.length != 4) {
            System.err.println("Invalid size of byte array");
            return 0;
        }

        int number = 0;
        for (byte b : theBytes) {
            number = (number << 8) + (b & 0xFF);
        }
        return number;
    }
}

