import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Scanner;


/**
 * This class represents the main functionality for cryptographic operations.
 * It includes capabilities for elliptic key pair generation, data encryption and decryption,
 * file signing, and signature verification using elliptic curve cryptography.
 * @author Andy Comfort
 * @author Caroline El Jazmi
 * @author Brandon Morgan
 */
public class Main {
    /**
     * Scanner to capture user input.
     */
    private static final Scanner scanner = new Scanner(System.in);

    /**
     * Path to the main file to operate on.
     */
    private static String messageFilePath;

    /**
     * Path to the public key file to operate on.
     */
    private static String publicKeyFilePath;


    /**
     * Path to the encrypted file to operate on.
     */
    private static String encryptedFilePath;

    /**
     * Path to the decrypted file to operate on.
     */
    private static String decryptedFilePath;

    /**
     * Path to the signature provided by the user as bytes.
     */
    private static String signFilePath;

    /**
     * Path to the passphrase provided by the user as bytes.
     */
    private static String passphraseFilePath;

    /**
     * Path to the private key file to operate on.
     */
    private static String privateKeyFilePath;

    // A large prime number used in cryptographic calculations
    private static final BigInteger R = BigInteger.valueOf(2).pow(446).subtract(new BigInteger("13818066809895115352007386748515426880336692474882178609894547503885"));


    /**
     * The main method that serves as the entry point for the application.
     * It processes command line arguments and initiates the user interaction for various cryptographic operations.
     *
     * @param args Command line arguments specifying file paths for operations.
     * @throws IOException If an I/O error occurs.
     */
    public static void main(String[] args) throws IOException {
        if (args.length > 1) {
            passphraseFilePath = args[0];
            messageFilePath = args[1];
            publicKeyFilePath = args[2];
            privateKeyFilePath = args[3];
            encryptedFilePath = args[4];
            decryptedFilePath = args[5];
            signFilePath = args[6];
        }

        while (true) {
            System.out.println("""
                    \n            MAIN MENU\s
                    1 - Generate elliptic key pair
                    2 - Encrypt data using public key
                    3 - Decrypt elliptic-encrypted data
                    4 - Sign a file
                    5 - Verify data and signature
                    6 - Exit""");
            System.out.print("\nEnter digit for mode of operation: ");

            String choice = scanner.nextLine();

            switch (choice) {
                case "1" -> handleGenerateKeyPairOption();
                case "2" -> handleEncryptOption();
                case "3" -> handleDecryptOption();
                case "4" -> handleGenerateSignatureOption();
                case "5" -> handleVerifySignOption();
                case "6" -> {
                    System.out.println("\nExiting...Goodbye!");
                    return;
                }
                default -> System.out.println("Invalid choice. Please try again.");
            }
        }
    }
    /**
     * Handles the generation of an elliptic key pair.
     * Provides options to generate a key pair from a passphrase or return to the main menu.
     */
    private static void handleGenerateKeyPairOption() {
        System.out.println("\n-------------------------------------");
        System.out.println("\nGenerate Elliptic Key Pair\n");
        System.out.println("""
            1 - Generate elliptic key pair from given passphrase
            2 - Go to Main Menu""");
        System.out.print("\nEnter Choice: ");
        String subChoice = scanner.nextLine();

        switch (subChoice) {
            case "1" -> {
                try {
                    if (passphraseFilePath == null) {
                        System.err.println("Passphrase file path is null.");
                        break;
                    }
                    byte[] passphraseBytes = readFile(passphraseFilePath);
                    if (passphraseBytes == null) {
                        System.err.println("Passphrase bytes are null. Check the readFile method.");
                        break;
                    }
                    if (publicKeyFilePath == null || privateKeyFilePath == null) {
                        System.err.println("Public or Private key file path is null.");
                        break;
                    }
                    KeyManager.generateKeyPairs(passphraseBytes, publicKeyFilePath, privateKeyFilePath);
                    // Rest of your code...
                } catch (Exception e) {
                    System.err.println("Error generating key pair: " + e.getMessage());
                }
                System.out.println("\n-------------------------------------");
            }
            case "2" -> {
                System.out.println("\n-------------------------------------");
            }
            default -> {
                System.out.println("Invalid choice. Please try again.");
                System.out.println("\n-------------------------------------");
            }
        }
    }
    /**
     * Handles the encryption of a data file.
     * Offers options to encrypt a data file using a public key or return to the main menu.
     */
    private static void handleEncryptOption() {
        System.out.println("\n-------------------------------------");
        System.out.println("\nChoose Your Encryption Method\n");
        System.out.println("""
                1 - File Encryption (Encrypt a specified file)
                2 - Text Encryption (Input and encrypt text manually)            
                3 - Go to Main Menu""");
        System.out.print("\nEnter Choice: ");
        String subChoice = scanner.nextLine();
        byte[] messageBytes = new byte[0];

        if (subChoice.equals("1")) {
            messageBytes = readFile(messageFilePath);
        } else if (subChoice.equals("2")){
            System.out.print("Please manually input text to be encrypted: ");
            messageBytes = scanner.nextLine().getBytes(StandardCharsets.UTF_8);
            writeByteData(messageFilePath, messageBytes);
        }

        switch (subChoice) {
            case "1", "2" -> {
                try {
                    SecureRandom random = new SecureRandom();
                    byte[] kBytes = new byte[56];
                    random.nextBytes(kBytes);

                    //k <- 4k(mod r)
                    BigInteger k = new BigInteger(1, kBytes);
                    k = k.multiply(BigInteger.valueOf(4)).mod(R);

                    Ed448Points V = readPublicKey();

                    //W <- k*V
                    Ed448Points W = Ed448Points.scalarMultiply(V, k);
                    //Z <- k*G
                    Ed448Points Z = Ed448Points.scalarMultiply(Ed448Points.getPublicGenerator(), k);

                    // (ka || ke) <- KMACXOF256(W_x, "", 2*448, "PK")
                    byte[] ka_ke = KMACXOF256.getKMACXOF256(W.getXBytes(), "".getBytes(), 2*448, "PK");
                    byte[] ka = Arrays.copyOfRange(ka_ke, 0, ka_ke.length/2);
                    byte[] ke = Arrays.copyOfRange(ka_ke, ka_ke.length/2, ka_ke.length);

                    //c <- KMACXOF256(ke, "", |m|, "PKE") XOR m
                    byte[] cPreXOR = KMACXOF256.getKMACXOF256(ke, "".getBytes(), messageBytes.length * 8, "PKE");
                    byte[] c = new byte[messageBytes.length];
                    for (int i = 0; i < messageBytes.length; i++) {
                        c[i] = (byte) (messageBytes[i] ^ cPreXOR[i]);
                    }

                    //t <- KMACXOF256(ka, messageAsBytes, 448, "PKA")
                    byte[] t = KMACXOF256.getKMACXOF256(ka, messageBytes, 448, "PKA");

                    //make one byte array of Z + c + t
                    byte[] pointZ = KeyManager.pointDataZip(Z);
                    byte[] finalCryptogram = KMACXOF256.concatByteArr(pointZ, c, t);

                    System.out.println("Encrypted Message Saved To " + encryptedFilePath);
                    writeByteData(encryptedFilePath, finalCryptogram);
                } catch (Exception e) {
                    System.err.println("Error Encrypting Data File: " + e.getMessage());
                }
                System.out.println("\n-------------------------------------");
            }
            case "3" -> {
                System.out.println("\n-------------------------------------");
            }
            default -> {
                System.out.println("Invalid choice. Please try again.");
                System.out.println("\n-------------------------------------");
            }
        }
    }

    /**
     * Handles the decryption of an elliptic-encrypted file.
     * Provides options to decrypt an encrypted file or return to the main menu.
     */
    private static void handleDecryptOption(){
        System.out.println("\n-------------------------------------");
        System.out.println("\nDecrypt Elliptic-Encrypted File\n");
        System.out.println("""
            1 - Decrypt Elliptic-Encrypted File
            2 - Go to Main Menu""");
        System.out.print("\nEnter Choice: ");
        String subChoice = scanner.nextLine();

        switch (subChoice) {
            case "1" -> {
                try {
                    byte[] passphraseBytes = readFile(passphraseFilePath);
                    byte[] messageBytes = readFile(messageFilePath);
                    // s <- KMACXOF256(pw, “”, 448, “SK”); s <- 4s (mod r)
                    byte[] secretBytes = KMACXOF256.getKMACXOF256(passphraseBytes, "".getBytes(), 448, "SK");
                    BigInteger secretBigInt = new BigInteger(1, secretBytes);
                    BigInteger s = secretBigInt.multiply(BigInteger.valueOf(4)).mod(R);

                    byte[] cryptogram = loadFile(new File("src/text_files/encrypted-message.txt"));
                    byte[] t = Arrays.copyOfRange(cryptogram, cryptogram.length - 56, cryptogram.length);
                    byte[] c = Arrays.copyOfRange(cryptogram, cryptogram.length - 56 - messageBytes.length, cryptogram.length - 56);
                    byte[] zData = Arrays.copyOfRange(cryptogram, 0, cryptogram.length - c.length - t.length);

                    Ed448Points Z = unzipData(zData);
                    Ed448Points W = Ed448Points.scalarMultiply(Z, s);

                    // (ka || ke) <- KMACXOF256(W_x, "", 2*448, "PK")
                    byte[] ka_ke = KMACXOF256.getKMACXOF256(W.getXBytes(), "".getBytes(), 2*448, "PK");
                    byte[] ka = Arrays.copyOfRange(ka_ke, 0, ka_ke.length / 2);
                    byte[] ke = Arrays.copyOfRange(ka_ke, ka_ke.length / 2, ka_ke.length);

                    byte[] mPreXOR = KMACXOF256.getKMACXOF256(ke, "".getBytes(), c.length * 8, "PKE");

                    byte[] m = new byte[c.length];
                    for (int i = 0; i < c.length; i++) {
                        m[i] = (byte) (c[i] ^ mPreXOR[i]);
                    }
                    byte[] t_prime = KMACXOF256.getKMACXOF256(ka, m, 448, "PKA");

                    if (Arrays.equals(t, t_prime)) {
                        System.out.println("Decrypted Message Saved To: " + decryptedFilePath);
                        writeByteData(decryptedFilePath, m);
                    } else {
                        System.out.println("Decryption Failed");
                    }
                } catch (Exception e) {
                    System.err.println("Error Decrypting Ciphertext: " + e.getMessage());
                }
                System.out.println("\n-------------------------------------");
            }
            case "2" -> {
                System.out.println("\n-------------------------------------");
            }
            default -> {
                System.out.println("Invalid choice. Please try again.");
                System.out.println("\n-------------------------------------");
            }
        }
    }
    /**
     * Handles the generation of a digital signature.
     * Offers options to generate a signature or return to the main menu.
     */
    private static void handleGenerateSignatureOption() {
        System.out.println("\n-------------------------------------");
        System.out.println("\nChoose Your Signature Generation Method\n");
        System.out.println("""
                1 - File Signature (Generate signature for a specified file)
                2 - Text Signature (Input and generate signature for text manually)           
                3 - Go to Main Menu""");
        System.out.print("\nEnter Choice: ");
        String subChoice = scanner.nextLine();
        byte[] messageBytes = new byte[0];

        if (subChoice.equals("1")) {
            messageBytes = readFile(messageFilePath);
        } else if (subChoice.equals("2")){
            System.out.print("Please manually input text to generate the signature: ");
            messageBytes = scanner.nextLine().getBytes(StandardCharsets.UTF_8);
        }
        switch (subChoice) {
            case "1", "2" -> {
                try {
                    byte[] passphraseBytes = readFile(passphraseFilePath);
                    System.out.println("Generating signature...");
                    SignatureManager.createFileSignature(messageBytes, passphraseBytes, signFilePath);
                } catch (Exception e) {
                    System.err.println("Error Generating Signature: " + e.getMessage());
                }
                System.out.println("\n-------------------------------------");
            }
            case "3" -> {
                System.out.println("\n-------------------------------------");
            }
            default -> {
                System.out.println("Invalid choice. Please try again.");
                System.out.println("\n-------------------------------------");
            }
        }
    }

    /**
     * Handles the verification of a digital signature against a file.
     * Provides options to verify a signature or return to the main menu.
     */
    private static void handleVerifySignOption() {
        System.out.println("\n-------------------------------------");
        System.out.println("Choose Method of Signature Verification\n");
        System.out.println("""
                1 - File Verification (Verify signature of a specified file)
                2 - Text Verification (Input and verify signature for text manually)          
                3 - Go to Main Menu""");
        System.out.print("\nEnter Choice: ");
        String subChoice = scanner.nextLine();

        byte[] messageBytes = new byte[0];

        if (subChoice.equals("1")) {
            messageBytes = readFile(messageFilePath);
        } else if (subChoice.equals("2")){
            System.out.print("Please manually input text to verify the signature: ");
            messageBytes = scanner.nextLine().getBytes(StandardCharsets.UTF_8);
        }

        switch (subChoice) {
            case "1", "2" -> {
                try {
                    byte[] sigBytes = readFile(signFilePath);
                    byte[] pubKeyBytes = readFile(publicKeyFilePath);
                    System.out.println("Verifying signature...");
                    SignatureManager.verifySignature(messageBytes, sigBytes, pubKeyBytes);
                } catch (Exception e) {
                    System.err.println("Error Verifying Signature: " + e.getMessage());
                }
                System.out.println("\n-------------------------------------");
            }
            case "3" -> {
                System.out.println("\n-------------------------------------");
            }
            default -> {
                System.out.println("Invalid choice. Please try again.");
                System.out.println("\n-------------------------------------");
            }
        }
    }

    /**
     * Loads a file and returns its content as a byte array.
     * Continues to attempt to read the file until successful.
     *
     * @param thefile The file to be read.
     * @return A byte array containing the file's contents.
     */
    private static byte[] loadFile(File thefile) {
        byte[] bytes = null;
        while (bytes == null)
            bytes = readByteData(String.valueOf(thefile));
        return bytes;
    }

    /**
     * Reads the contents of a file located at the specified file path and returns it as a byte array.
     * If an error occurs during the file reading process, it prints an error message and returns null.
     *
     * @param filePath The path of the file to be read.
     * @return A byte array containing the contents of the file, or null if an error occurs.
     * @throws IOException If there is an error reading the file.
     */
    private static byte[] readFile(String filePath) {
        try {
            return Files.readAllBytes(Paths.get(filePath));
        } catch (IOException e) {
            System.out.println("Error reading file: " + filePath);
            return null;
        }
    }

    /**
     * Reads a byte array from a file at the specified path.
     *
     * @param path The path of the file to be read.
     * @return A byte array containing the file's contents, or null if the file is invalid.
     */
    public static byte[] readByteData(final String path) {
        byte[] theBytes = null;

        try {
            theBytes = Files.readAllBytes(Paths.get(path));
        } catch (Exception easy) {
            System.out.println("File Invalid");
        }
        return theBytes;
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
     * Reads a public key from a byte array.
     *
     * @return An Ed448Points object representing the public key, or null if an error occurs.
     */
    private static Ed448Points readPublicKey() {
        try {
            // Read the byte data from the file
            byte[] publicKeyBytes = readByteData(publicKeyFilePath);

            // Convert the byte array back into a Point object.
            return unzipData(publicKeyBytes);
        } catch (Exception e) {
            System.out.println("Error reading public key file: " + publicKeyFilePath);
            return null;
        }
    }
    /**
     * Converts a byte array into an Ed448Points object.
     *
     * @param pointData The byte array representing the point data.
     * @return An Ed448Points object, or null if conversion fails.
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
     * Converts a specific portion of a byte array into an integer array.
     *
     * @param pointData The byte array containing the data to be converted.
     * @return An integer array derived from the byte array.
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
     * @param theBytes A byte array of length 4.
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


