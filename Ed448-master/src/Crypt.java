import java.security.SecureRandom;
import java.util.Arrays;


/**
 * Crypt class provides methods to handle cryptographic operations.
 * The class uses the KMACXOF256 cryptographic function.
 *
 * @author Andy Comfort
 * @author Caroline El Jazmi
 * @author Brandon Morgan
 */
public class Crypt {

    /** Determines if the cryptographic operation was valid. */
    private final boolean isValid;

    /** Contains the data after a cryptographic operation. */
    private final byte[] data;

    /** Specifies the length of the key. */
    private static final int KEY_LENGTH = 64;

    /** Specifies the length of the key set. */
    private static final int KEYSET_LENGTH = 1024;

    /** Specifies the length of the tag. */
    private static final int TAG_LENGTH = 512;

    /** Custom string constant used for cryptographic operations. */
    private static final String CUSTOM_STRING = "S";

    /** Symbolic constant for symmetric key encryption. */
    private static final String SYMM_KEY_ENC = "SKE";

    /** Symbolic constant for symmetric key authentication. */
    private static final String SYMM_KEY_AUTH = "SKA";


    /**
     * Constructs a Crypt object with the specified validity status and data.
     *
     * @param isValid validity status of the data
     * @param data    data array
     */
    public Crypt(boolean isValid, byte[] data) {
        this.isValid = isValid;
        this.data = data;
    }

    public byte[] getData() {
        return data;
    }

    public boolean isValid() {
        return isValid;
    }


    /**
     * Encrypts the provided input using the specified password.
     *
     * @param thePassword password for encryption
     * @param theInput    data to encrypt
     * @return encrypted data
     */
    public static byte[] encrypt(byte[] thePassword, byte[] theInput) {
        SecureRandom gen = new SecureRandom();
        byte[] rnd = new byte[KEY_LENGTH];
        gen.nextBytes(rnd);

        byte[] keys = KMACXOF256.getKMACXOF256(KMACXOF256.concatByteArr(rnd, thePassword), new byte[]{}, KEYSET_LENGTH, CUSTOM_STRING);
        byte[] key1 = Arrays.copyOfRange(keys, 0, KEY_LENGTH);
        byte[] key2 = Arrays.copyOfRange(keys, KEY_LENGTH, 128);

        byte[] mask = KMACXOF256.getKMACXOF256(key1, new byte[]{}, theInput.length * 8, SYMM_KEY_ENC);
        byte[] enc = KMACXOF256.xorBytes(mask, theInput); // modified line
        byte[] tag = KMACXOF256.getKMACXOF256(key2, theInput, TAG_LENGTH, "SKA");

        return KMACXOF256.concatByteArr(KMACXOF256.concatByteArr(rnd, enc), tag);
    }


    /**
     * Decrypts the encoded data using the specified password.
     *
     * @param thePassword password for decryption
     * @param theEncoded  encoded data to decrypt
     * @return a Crypt object containing the decryption validity and decrypted data
     */
    public static Crypt decrypt(byte[] thePassword, byte[] theEncoded) {
        byte[] rnd = Arrays.copyOfRange(theEncoded, 0, KEY_LENGTH);
        byte[] msg = Arrays.copyOfRange(theEncoded, KEY_LENGTH, theEncoded.length - KEY_LENGTH);
        byte[] tag = Arrays.copyOfRange(theEncoded, theEncoded.length - KEY_LENGTH, theEncoded.length);

        byte[] concatenatedBytes = KMACXOF256.concatByteArr(rnd, thePassword);
        byte[] keys = KMACXOF256.getKMACXOF256(concatenatedBytes, new byte[]{}, KEYSET_LENGTH, CUSTOM_STRING);

        byte[] key1 = Arrays.copyOfRange(keys, 0, KEY_LENGTH);
        byte[] key2 = Arrays.copyOfRange(keys, KEY_LENGTH, 128);

        byte[] mask = KMACXOF256.getKMACXOF256(key1, new byte[]{}, msg.length * 8, SYMM_KEY_ENC);

        byte[] dec = KMACXOF256.xorBytes(mask, msg);
        byte[] ctag = KMACXOF256.getKMACXOF256(key2, dec, TAG_LENGTH, SYMM_KEY_AUTH);

        return new Crypt(Arrays.equals(tag, ctag), dec);
    }


    /**
     * Computes a hash of the provided data.
     *
     * @param data data to hash
     * @return a string representation of the hash
     */
    public static String computeHash(byte[] data) {
        byte[] hash = KMACXOF256.getKMACXOF256("".getBytes(), data, TAG_LENGTH, "D");
        StringBuilder result = new StringBuilder();
        for (byte b : hash) {
            result.append(String.format("%02x", b));
        }
        return result.toString();
    }


    /**
     * Computes an authentication tag for the given data using the provided password.
     *
     * @param pw   password for authentication
     * @param data data to authenticate
     * @return a string representation of the authentication tag
     */
    public static String computeAuthTag(byte[] pw, byte[] data) {
        byte[] hash = KMACXOF256.getKMACXOF256(pw, data, TAG_LENGTH, "T");
        StringBuilder result = new StringBuilder();
        for (byte b : hash) {
            result.append(String.format("%02x", b));
        }
        return result.toString();
    }


}
