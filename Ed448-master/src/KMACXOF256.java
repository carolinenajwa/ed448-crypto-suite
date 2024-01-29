import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Objects;


/**
 * Implements the KMACXOF256 cryptographic function.
 * Based on Markku-Juhani Saarinen’s SHA-3 C implementation (https://github.com/mjosaarinen/tiny_sha3/)
 *
 * @author Andy Comfort
 * @author Caroline El Jazmi
 * @author Brandon Morgan
 */
public class KMACXOF256 {

    /** Stores the result of computation. */
    private static byte[] result;

    /** Constants used in Keccak round calculations. */
    private static final long[] keccakf_rndc = {
            0x0000000000000001L, 0x0000000000008082L, 0x800000000000808aL,
            0x8000000080008000L, 0x000000000000808BL, 0x0000000080000001L,
            0x8000000080008081L, 0x8000000000008009L, 0x000000000000008aL,
            0x0000000000000088L, 0x0000000080008009L, 0x000000008000000aL,
            0x000000008000808bL, 0x800000000000008bL, 0x8000000000008089L,
            0x8000000000008003L, 0x8000000000008002L, 0x8000000000000080L,
            0x000000000000800aL, 0x800000008000000aL, 0x8000000080008081L,
            0x8000000000008080L, 0x0000000080000001L, 0x8000000080008008L
    };

    /** Indices used for bit permutation in Keccak calculations. */
    private static final int[] keccakf_piln = {
            10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
            15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1
    };

    /** Rotation offsets used in Keccak calculations. */
    private static final int[] keccakf_rotc = {
            1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
            27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44
    };


    /**
     * Calculates the KMACXOF256 hash of the input data using the specified key.
     *
     * @param K The key used in the calculation.
     * @param X The input data to be hashed.
     * @param L The desired length of the output hash.
     * @param S Customization string for the hash.
     * @return The computed KMACXOF256 hash.
     * @throws IllegalArgumentException if any input is null.
     */
    public static byte[] getKMACXOF256(byte[] K, byte[] X, int L, String S) {
        // Validate conditions
        if (K == null || X == null || S == null) {
            throw new IllegalArgumentException("Key, input, or customization string must not be null.");
        }

//        System.out.println("Checkpoint: KMACXOF256 - Start");
//        System.out.println("Input K: " + Arrays.toString(K));
//        System.out.println("Input X: " + Arrays.toString(X));
//        System.out.println("Length L: " + L);
//        System.out.println("Customization String S: " + S);

        // Format the key by encoding it as a string.
        String keyAsString = new String(K, StandardCharsets.UTF_8);
        byte[] encodedKey = encode_string(keyAsString);

//        System.out.println("Encoded Key: " + Arrays.toString(encodedKey));

        // Apply byte padding to the key to meet the block size requirements of cSHAKE256.
        int blockSize = 136; // Block size for cSHAKE256 in bytes.
        byte[] bytePaddedKey = bytepad(encodedKey, blockSize);

//        System.out.println("Byte Padded Key: " + Arrays.toString(bytePaddedKey));


        // Prepare the initial input for cSHAKE256 by concatenating the byte-padded key and the original input.
        byte[] initialInput = concatByteArr(bytePaddedKey, X);

        // right-encoded value of zero must be appended to the input.
        byte[] rightEncodedZero = right_encode(0); // This function should be defined as per your use case.

        byte[] finalInput = concatByteArr(initialInput, rightEncodedZero);

//        System.out.println("Final Input for cSHAKE256: " + Arrays.toString(finalInput));


        // Compute the cSHAKE256 hash. This function must be defined to return the cSHAKE256 hash of the input.
        result = cSHAKE256(finalInput, L, "KMAC", S);

//        System.out.println("cSHAKE256 Result: " + Arrays.toString(result)); // Test

        return result;
    }


    /**
     * Calculates the cSHAKE256 hash of the input data.
     *
     * @param X The input data to be hashed.
     * @param L The desired length of the output hash.
     * @param N The function name for the hash.
     * @param S Customization string for the hash.
     * @return The computed cSHAKE256 hash.
     */
    public static byte[] cSHAKE256(byte[] X, int L, String N, String S) {
        // If both the function name and customization string are empty, revert to SHAKE256
        if (N.isEmpty() && S.isEmpty()) {
            return SHAKE256(X, L);
        }

        // Encode the function name and the customization string
        byte[] encodedFuncName = encode_string(new String(N.getBytes(StandardCharsets.UTF_8)));
        byte[] encodedCustStr = encode_string(new String(S.getBytes(StandardCharsets.UTF_8)));

        // Merge the encoded strings
        byte[] customization = concatByteArr(encodedFuncName, encodedCustStr);

        // Pad the customization string and merge it with the input
        byte[] paddedCustomization = bytepad(customization, 136);
        byte[] combinedInput = concatByteArr(paddedCustomization, X);

        // Big-end interp
        combinedInput = concatByteArr(combinedInput, new byte[]{0x04});

        // Apply the sponge construction to get the final hash w/ keccak variant function
        return sponge(combinedInput, L, 512);
    }


    /**
     * Calculates the SHAKE256 hash of the input data.
     *
     * @param X The input data to be hashed.
     * @param L The desired length of the output hash.
     * @return The computed SHAKE256 hash.
     */
    public static byte[] SHAKE256(byte[] X, int L) {
        // The 'rate' of SHAKE256 is 136 bytes.
        final int rateInBytes = 136;

        // Calculate bytes needed to be added to the input to make its length a multiple of the rate.
        int paddingLength = rateInBytes - (X.length % rateInBytes);

        // Create a new array that has space for the original input plus the padding.
        byte[] paddedInput = Arrays.copyOf(X, X.length + 1);

        // Single byte padding
        byte paddingByte = (paddingLength == 1) ? (byte) 0x9F : 0x1F;
        paddedInput[X.length] = paddingByte;

        // Sponge function that produces the final hash.
        return sponge(paddedInput, L, rateInBytes * 8); // rateInBytes * 8 converts rate from bytes to bits.
    }


    /**
     * Applies the Iota transformation to the input state.
     *
     * @param inputState The current state.
     * @param round The current round number.
     * @return The state after the Iota transformation.
     * @throws IllegalArgumentException if the input state is invalid.
     */
    private static long[] iota(long[] inputState, int round) {
        if (inputState == null || inputState.length != 25 || round < 0 || round >= keccakf_rndc.length) {
            throw new IllegalArgumentException("Invalid input to iota function");
        }
        inputState[0] ^= keccakf_rndc[round];
        return inputState;
    }

    /**
     * Applies the Chi transformation to the input state.
     *
     * @param inputState The current state.
     * @return The state after the Chi transformation.
     * @throws IllegalArgumentException if the input state is invalid.
     */
    private static long[] chi(long[] inputState) {
        if (inputState == null || inputState.length != 25) {
            throw new IllegalArgumentException("Invalid input to chi function");
        }
        long[] stateOut = new long[25];
        for (int i = 0; i < 5; i++) {
            for (int j = 0; j < 5; j++) {
                long tmp = ~inputState[(i + 1) % 5 + 5 * j] & inputState[(i + 2) % 5 + 5 * j];
                stateOut[i + 5 * j] = inputState[i + 5 * j] ^ tmp;
            }
        }
        return stateOut;
    }

    /**
     * Applies the Rho and Pi transformations to the input state.
     *
     * @param inputState The current state.
     * @return The state after the Rho and Pi transformations.
     * @throws IllegalArgumentException if the input state is invalid.
     */
    private static long[] rhoPhi(long[] inputState) {
        if (inputState == null || inputState.length != 25) {
            throw new IllegalArgumentException("Invalid input to rhoPhi function");
        }
        long[] stateOut = new long[25];
        stateOut[0] = inputState[0]; // Copy the first value directly
        long t = inputState[1], temp;
        for (int i = 0; i < 24; i++) {
            int ind = keccakf_piln[i];
            temp = inputState[ind];
            stateOut[ind] = rotateLeft(t, keccakf_rotc[i]); // Rotation
            t = temp;
        }
        return stateOut;
    }


    /**
     * Applies the Theta transformation to the input state.
     *
     * @param stateIn The current state.
     * @return The state after the Theta transformation.
     * @throws IllegalArgumentException if the input state is invalid.
     */
    private static long[] theta(long[] stateIn) {
        if (stateIn == null || stateIn.length != 25) {
            throw new IllegalArgumentException("Invalid input to theta function");
        }
        long[] stateOut = new long[25];
        long[] C = new long[5];
        // XOR fold columns
        for (int i = 0; i < 5; i++) {
            C[i] = stateIn[i] ^ stateIn[i + 5] ^ stateIn[i + 10] ^ stateIn[i + 15] ^ stateIn[i + 20];
        }
        // Mix each bit with two other bits
        for (int i = 0; i < 5; i++) {
            long d = C[(i + 4) % 5] ^ rotateLeft(C[(i + 1) % 5], 1);
            for (int j = 0; j < 5; j++) {
                stateOut[i + 5 * j] = stateIn[i + 5 * j] ^ d;
            }
        }
        return stateOut;
    }


    /**
     * Encodes the given length value (x) using the left-encode scheme.
     *
     * @param x The length value to be encoded.
     * @return A byte array representing the left-encoded length.
     */
    public static byte[] left_encode(long x) {
        // Special case for zero length.
        if (x == 0) {
            return new byte[]{1, 0};
        }

        // Convert the length into a byte array (big-endian).
        ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
        buffer.putLong(x);
        byte[] bytes = buffer.array();

        // Find the first non-zero byte (MSB of the length).
        int startIndex = 0;
        while (startIndex < bytes.length && bytes[startIndex] == 0) {
            startIndex++;
        }

        // Determine the number of significant bytes (excluding leading zeros).
        int numSignificantBytes = bytes.length - startIndex;

        // Prepare the output buffer.
        byte[] out = new byte[numSignificantBytes + 1]; // +1 for the size byte at the beginning.

        // The first byte indicates the number of significant bytes.
        out[0] = (byte) numSignificantBytes;

        // Copy the significant bytes into the output buffer.
        System.arraycopy(bytes, startIndex, out, 1, numSignificantBytes);

        return out;
    }


    /**
     * Encodes the given length value (x) using the right-encode scheme.
     *
     * @param x The length value to be encoded.
     * @return A byte array representing the right-encoded length.
     */
    public static byte[] right_encode(long x) {
        // Special case for zero length.
        if (x == 0) {
            return new byte[]{0, 1};
        }

        // Convert the length into a byte array (big-endian).
        ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
        buffer.putLong(x);
        byte[] bytes = buffer.array();

        // Find the first non-zero byte (MSB of the length).
        int startIndex = 0;
        while (startIndex < bytes.length && bytes[startIndex] == 0) {
            startIndex++;
        }

        // Determine number of significant bytes (excluding leading zeros).
        int numSignificantBytes = bytes.length - startIndex;

        // Prepare output buffer.
        byte[] out = new byte[numSignificantBytes + 1]; // +1 for the size byte at the end.

        // Copy the significant bytes into the output buffer.
        System.arraycopy(bytes, startIndex, out, 0, numSignificantBytes);

        // Last byte indicates the number of significant bytes.
        out[out.length - 1] = (byte) numSignificantBytes;

        return out;
    }


    /**
     * Encodes the given string.
     * The result includes the length of the original string in bits followed by
     * the string bytes.
     *
     * @param S The string to be encoded.
     * @return A byte array representing the encoded string.
     * @throws IllegalArgumentException If the input string is null.
     */
    public static byte[] encode_string(String S) {
        // Validate input string is not null
        if (S == null) {
            throw new IllegalArgumentException("Input string must not be null.");
        }

        // Convert the String to a byte array
        byte[] strBytes = S.getBytes(StandardCharsets.UTF_8); // Ensure consistent encoding (e.g., UTF-8)

        // Encode the length of the original string in bits
        long bitLength = strBytes.length * 8L;
        byte[] lengthEncoded = left_encode(bitLength);

        // Prepare the output array w/ appropriate length
        int totalLength = lengthEncoded.length + strBytes.length;
        byte[] encodedString = new byte[totalLength];

        // Copy the length encoding and the original string bytes into the output array
        System.arraycopy(lengthEncoded, 0, encodedString, 0, lengthEncoded.length);
        System.arraycopy(strBytes, 0, encodedString, lengthEncoded.length, strBytes.length);

        // Return the combined length encoding and original string bytes
        return encodedString;
    }


    /**
     * Encodes the given byte array.
     * The result includes the length of the original byte array in bits followed by
     * the byte array itself.
     *
     * @param inputBytes The byte array to be encoded.
     * @return A byte array representing the encoded byte array.
     * @throws IllegalArgumentException If the input byte array is null.
     */
    public static byte[] encode_byte_array(byte[] inputBytes) {
        // Validate input byte array is not null
        if (inputBytes == null) {
            throw new IllegalArgumentException("Input byte array must not be null.");
        }

        // Encode the length of the original byte array in bits
        long bitLength = inputBytes.length * 8L;
        byte[] lengthEncoded = left_encode(bitLength);

        // Prepare the output array w/ appropriate length
        int totalLength = lengthEncoded.length + inputBytes.length;
        byte[] encodedByteArray = new byte[totalLength];

        // Copy the length encoding and the original byte array into the output array
        System.arraycopy(lengthEncoded, 0, encodedByteArray, 0, lengthEncoded.length);
        System.arraycopy(inputBytes, 0, encodedByteArray, lengthEncoded.length, inputBytes.length);

        // Return the combined length encoding and original byte array
        return encodedByteArray;
    }


    /**
     * Applies byte padding to the given byte array (X) based on a specified block size (w).
     *
     * @param X The byte array to be padded.
     * @param w The block size used for padding.
     * @return A byte array representing the padded input.
     * @throws IllegalArgumentException If X is null or w is less than or equal to 0.
     */
    public static byte[] bytepad(byte[] X, int w) {
        // Validate conditions
        if (X == null) {
            throw new IllegalArgumentException("X byte array must not be null.");
        }
        if (w <= 0) {
            throw new IllegalArgumentException("w size must be greater than 0.");
        }

        // Encode the block size
        byte[] encodedBlockSize = left_encode(w);

        // Calculate the total length for the new array
        int initialLength = encodedBlockSize.length + X.length;
        int paddingLength = (w - (initialLength % w)) % w; // Additional modulo ensures no extra padding if already multiple of w.
        int totalLength = initialLength + paddingLength;

        // Initialize the new array and copy the encoded block size
        byte[] output = Arrays.copyOf(encodedBlockSize, totalLength);
        System.arraycopy(X, 0, output, encodedBlockSize.length, X.length);

        return output;
    }

    /**
     * Concatenates multiple byte arrays into a single byte array.
     *
     * @param arrays Varargs parameter of byte arrays to concatenate.
     * @return The concatenated byte array.
     * @throws NullPointerException If any of the input byte arrays is null.
     */
    public static byte[] concatByteArr(byte[]... arrays) {
        // Validate that all arrays are non-null
        for (byte[] array : arrays) {
            Objects.requireNonNull(array, "Input byte arrays must not be null");
        }

        // Calculate the total length of the result array
        int totalLen = 0;
        for (byte[] array : arrays) {
            totalLen += array.length;
        }

        // Efficiently allocate space for the merged array
        ByteBuffer mergedBuffer = ByteBuffer.allocate(totalLen);

        // Append arrays to the merged array
        for (byte[] array : arrays) {
            mergedBuffer.put(array);
        }

        return mergedBuffer.array();
    }

    /**
     * Implements the sponge construction, a cryptographic primitive used in the
     * Keccak (SHA-3) family of cryptographic functions.
     *
     * @param inByteArr The input byte array.
     * @param bitLen    Desired bit length of the output.
     * @param capacity  Part of the state that is not affected directly by the input.
     * @return The sponge result as a byte array.
     */
    private static byte[] sponge(byte[] inByteArr, int bitLen, int capacity) {
        int rate = 1600 - capacity;
        byte[] paddedInput = getPaddedInput(inByteArr, rate);
        long[][] states = convertArrayToState(paddedInput, capacity);

        long[] cumulativeState = performAbsorption(states, 1600);
        long[] output = performSqueezing(cumulativeState, rate, bitLen);

        return convertStateToArray(output, bitLen);
    }

    /**
     * Converts a segment of a byte array, starting from a specified index, into a 64-bit word.
     *
     * @param startIndex The start index in the byte array.
     * @param arr        The input byte array.
     * @return The 64-bit word.
     * @throws IllegalArgumentException If the byte array doesn't have enough bytes starting from the specified index.
     */
    public static long convertByteToWord(int startIndex, byte[] arr) {
        if (arr.length < startIndex + 8) {
            throw new IllegalArgumentException("Insufficient bytes, index out of range.");
        }

        long number = 0;
        for (int i = 0; i < 8; i++) {
            number |= ((long) arr[startIndex + i] & 0xff) << (8 * i);
        }

        return number;
    }


    /**
     * Converts an array of bytes into an array of state arrays used in the Keccak hashing process.
     *
     * @param arr The input byte array, typically the message to be hashed.
     * @param cap The capacity (c) in bits; part of the state that is not affected directly by the input.
     * @return A 2D array of longs (flattened 3D), representing the states derived from the input byte array.
     * @throws IllegalArgumentException if input byte array is null or empty, or if capacity is not within valid range.
     */
    public static long[][] convertArrayToState(byte[] arr, int cap) {
        // Validate the input array and capacity.
        if (arr == null || arr.length == 0) {
            throw new IllegalArgumentException("Input cannot be null or empty.");
        }
        if (cap <= 0 || cap >= 1600) {
            throw new IllegalArgumentException("Capacity must be positive and less than 1600.");
        }

        // Calculate the rate (r) by subtracting the capacity from 1600 (the maximum length in bits of the state).
        int rate = 1600 - cap;

        // Determine the number of state arrays needed based on the length of the input byte array.
        int numOfStates = (arr.length * 8) / rate;

        // Initialize a 2D array to hold the state arrays.
        long[][] stateOut = new long[numOfStates][25];

        int currPos = 0; // To keep track of the position in the input byte array.

        // Iterate over each state array to be filled.
        for (int i = 0; i < numOfStates; i++) {
            long[] state = new long[25]; // Each state is an array of 25 longs.

            // Fill the state array with words (64-bit longs) converted from the byte array.
            for (int j = 0; j < rate / 64; j++) {
                state[j] = convertByteToWord(currPos, arr); // Convert the next 8 bytes to a 64-bit long.
                currPos += 8; // Proceed to the next 8 bytes (64 bits)
            }
            stateOut[i] = state; // Assign the filled state array to the corresponding position in the 2D array.
        }
        return stateOut; // Return the 2D array of state arrays.
    }


    /**
     * Converts the internal state array used in the hashing algorithm into a byte array of the specified length.
     *
     * @param state The state array, represented as an array of longs (64-bit integers).
     * @param bitLen The desired bit length of the output.
     * @return A byte array constructed from the state array.
     * @throws IllegalArgumentException if input validation fails.
     */
    public static byte[] convertStateToArray(long[] state, int bitLen) {
        // Validation
        if (state == null || state.length == 0) {
            throw new IllegalArgumentException("State cannot be null or empty.");
        }
        if (state.length * 64 < bitLen) {
            throw new IllegalArgumentException("State is of insufficient length to produce desired bit length.");
        }

        // Initialize the output byte array, which will contain the specified number of bits (converted to bytes).
        byte[] arrOut = new byte[bitLen / 8];
        int currPos = 0; // Index to track the current position in the state array.

        // Continue the conversion process until the desired bit length is reached.
        while (currPos * 64 < bitLen) {
            long currWord = state[currPos]; // Retrieve the current 64-bit segment of the state array.

            // Calculate the number of bytes to write from this 64-bit word. It's typically 8 (for a full 64-bit word),
            int numByteRange = (currPos + 1) * 64 > bitLen ? (bitLen - currPos * 64) / 8 : 8;

            // Extract each byte from the current 64-bit word and assign it to the appropriate position in the output byte array.
            for (int byteNum = 0; byteNum < numByteRange; byteNum++) {
                arrOut[currPos * 8 + byteNum] = (byte) (currWord >>> (byteNum * 8) & 0xFF);
            }
            currPos++;  // Move to the next 64-bit segment (word) in the state array.
        }

        return arrOut;  // Return the final byte array, representing the desired number of bits from the state array.
    }

    /**
     * Adjusts the input byte array to the required rate by applying padding if necessary.
     *
     * @param input The input byte array to be padded.
     * @param rate The desired rate (in bits) for the padding.
     * @return Returns the input byte array if its length is a multiple of rate/8; otherwise, a padded array.
     */
    private static byte[] getPaddedInput(byte[] input, int rate) {
        if (input.length % (rate / 8) != 0) {
            return keccakPadding(rate, input);
        } else {
            return input;
        }
    }

    /**
     * Accumulates the state values through a series of keccak permutations.
     *
     * @param states An array of state matrices to be absorbed.
     * @param width The width (in bits) of the keccak function.
     * @return The cumulative state after performing the absorption phase.
     */
    private static long[] performAbsorption(long[][] states, int width) {
        long[] cumulativeState = new long[25];
        for (long[] state : states) {
            cumulativeState = keccakPermutation(xorStates(cumulativeState, state), width, 24);
        }
        return cumulativeState;
    }

    /**
     * Extracts the output values from the provided cumulative state.
     *
     * @param cumulativeState The state from which the output is to be squeezed.
     * @param rate The rate (in bits) for squeezing.
     * @param bitLen The length (in bits) of the desired output.
     * @return The squeezed output as a long array.
     */
    private static long[] performSqueezing(long[] cumulativeState, int rate, int bitLen) {
        long[] output = {};
        int offset = 0;
        do {
            output = Arrays.copyOf(output, offset + rate / 64);
            System.arraycopy(cumulativeState, 0, output, offset, rate / 64);
            offset += rate / 64;
            cumulativeState = keccakPermutation(cumulativeState, 1600, 24);
        } while (output.length * 64 < bitLen);
        return output;
    }


    /**
     * Computes the bitwise XOR of two state arrays.
     *
     * @param arr1 The first state array.
     * @param arr2 The second state array.
     * @return The resulting state array after the XOR operation.
     * @throws IllegalArgumentException if any of the input arrays is null or if their lengths are not 25.
     */
    public static long[] xorStates(long[] arr1, long[] arr2) {
        // Check if either of the state arrays is null, and if so, throw an exception.
        if(arr1 == null || arr2 == null) {
            throw new IllegalArgumentException("Input states must not be null");
        }
        // Check if either of the state arrays doesn't have a length of 25, and if so, throw an exception.
        if(arr1.length != 25 || arr2.length != 25) {
            throw new IllegalArgumentException("Input states must have a length of 25");
        }

        // Iterate over each element in the state arrays.
        for (int i = 0; i < 25; i++) {
            // Perform an XOR operation between the corresponding elements of the two state arrays
            // and assign the result back to the first state array.
            arr1[i] ^= arr2[i];
        }

        // Return the first state array, which now contains the result of the XOR operations.
        return arr1;
    }

    /**
     * Rotates the bits of the given value to the left by the specified number of positions.
     *
     * @param val The value whose bits are to be rotated.
     * @param shift The number of positions to rotate left.
     * @return The value with its bits rotated left.
     * @throws IllegalArgumentException if the shift value is negative.
     */
    public static long rotateLeft(long val, int shift) {
        if(shift < 0) {
            throw new IllegalArgumentException("Shift value must be non-negative");
        }
        // Use Java's built-in method for clarity and performance
        return Long.rotateLeft(val, shift);
    }


    /**
     * Computes the bitwise XOR of two byte arrays.
     *
     * @param b1 The first byte array.
     * @param b2 The second byte array.
     * @return A new byte array that is the result of xoring each byte from b1 and b2.
     * @throws IllegalArgumentException if the input arrays have different lengths.
     */
    public static byte[] xorBytes(byte[] b1, byte[] b2) {
        if (b1.length != b2.length) throw new IllegalArgumentException("Input arrays are of different lengths");
        byte[] out = new byte[b1.length];
        for (int i = 0; i < b1.length; i++) {
            out[i] = (byte) (b1[i] ^ b2[i]);
        }
        return out;
    }


    /**
     * Pads the given byte array according to the Keccak padding rules.
     *
     * @param rate The desired rate (in bits) for the padding. It should be a positive multiple of 8.
     * @param arr The input byte array to be padded.
     * @return A new byte array that contains the original data followed by the necessary padding.
     * @throws IllegalArgumentException if the input array is null, or if the rate is not a positive multiple of 8.
     */
    public static byte[] keccakPadding(int rate, byte[] arr) {
        // Ensure input is not null and rate is a positive multiple of 8
        if (arr == null) {
            throw new IllegalArgumentException("Input must not be null");
        }
        if (rate <= 0 || rate % 8 != 0) {
            throw new IllegalArgumentException("Rate must be a positive multiple of 8");
        }

        // Calculate how much padding is needed to make the input length a multiple of the rate
        int paddingLength = (rate / 8) - arr.length % (rate / 8);
        byte[] paddedInput = new byte[arr.length + paddingLength];

        // Copy original input to padded array
        System.arraycopy(arr, 0, paddedInput, 0, arr.length);

        // Set the last byte to 0x80 to signify the end of the padding according to Keccak's standard
        paddedInput[paddedInput.length - 1] = (byte) 0x80;

        return paddedInput; // Return the padded input
    }


    /**
     * Performs the Keccak permutation on the given state for a specified number of rounds.
     *
     * @param state The initial state represented as a 1-dimensional array of longs.
     * @param bitLen The bit length of the state. It must be a positive multiple of 25.
     * @param rounds The number of rounds the permutation should be applied.
     * @return A new state array after applying the specified number of permutation rounds.
     * @throws IllegalArgumentException if the state is null, not of length 25; if bitLen is not a positive multiple of 25;
     * or if rounds is not a positive integer.
     */
    public static long[] keccakPermutation(long[] state, int bitLen, int rounds) {
        // Validate input parameters.
        if (state == null || state.length != 25) {
            throw new IllegalArgumentException("State must be a 5x5 array.");
        }
        if (bitLen <= 0 || bitLen % 25 != 0) {
            throw new IllegalArgumentException("bitLen must be a positive multiple of 25.");
        }
        if (rounds <= 0) {
            throw new IllegalArgumentException("Rounds must be a positive integer.");
        }

        // Calculate 'l' directly within the function, removing the need for a separate getFloorLog method.
        int value = bitLen / 25;
        int l = 0;
        while (value > 1) {
            value >>>= 1; // Unsigned right shift assignment.
            l++;
        }

        int totalRounds = 12 + 2 * l; // Number of total rounds based on 'l'.
        int startRound = totalRounds - rounds; // Calculate the start round.

        long[] currentState = state; // Initialize the current state.

        // Apply the specified number of permutation rounds.
        for (int i = startRound; i < totalRounds; i++) {
            currentState = iota(chi(rhoPhi(theta(currentState))), i); // Apply the permutation rounds.
        }

        return currentState; // Return the state after the permutations.
    }






}
