import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * This class can be used to generate multiple subkeys from a user-defined
 * key. It implements a Hashed Message Authentication Code (HMAC)-based key
 * derivation function (HKDF) as defined in the
 * <a href="https://datatracker.ietf.org/doc/html/rfc5869">RFC 5869</a>.
 * For the purposes of this application, a 16 character long user-defined
 * key, consisting of letters (lowercase and uppercase) and numbers, is
 * assumed, and subkeys of the same length and composition are generated.
 */
public class SubkeyGenerator {

    /**
     * The MAC algorithm to be implemented by any {@link Mac} objects. This
     * string has to be a name specified in the Java Cryptography Architecture
     * (JCA) Standard Algorithm Name Documentation.
     */
    private static final String MAC_ALGORITHM = "HmacSHA256";

    /**
     * The alphabet used to convert the raw bytes provided by the HKDF to
     * characters using the Base62 encoding.
     */
    private static final char[] BASE62_ALPHABET =
            "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
                    .toCharArray();

    /**
     * Generates a number of subkeys using the userDefinedKey as input keying
     * material. For each subkey, the "extract-then-expand" paradigm is
     * followed as dictated by the HKDF structure.
     *
     * @param userDefinedKey the user-defined key
     * @param numberOfSubkeys the desired number of subkeys that should be
     *                        returned; it should be equal to the number of
     *                        rounds of encryption/ decryption
     * @return a String array of subkeys
     * @throws NoSuchAlgorithmException in case the algorithm specified for
     * the Mac object in the extract() or expand() methods is not available
     * @throws InvalidKeyException in case the key used to initialize the Mac
     * object in the extract() or expand() methods is inappropriate
     * @throws IllegalArgumentException in case the user-defined key is not
     * 16 characters in length
     */
    public static String[] generateSubkeys(String userDefinedKey,
                                           int numberOfSubkeys)
            throws NoSuchAlgorithmException, InvalidKeyException,
            IllegalArgumentException {
        if (userDefinedKey.length() != 16) {
            throw new InvalidParameterException("Key length must be 16");
        }

        String[] subkeys = new String[numberOfSubkeys];

        // Converting the user-defined key to bytes using UTF_8.
        byte[] userDefinedKeyBytes = userDefinedKey
                .getBytes(StandardCharsets.UTF_8);

        for (int i = 0; i < numberOfSubkeys; i++) {

            /*
             * This "info" value is used to derive different subkeys from the
             * same master key. The "context" that changes in this
             * implementation is the round of encryption.
             */
            byte[] info = ("subkey_" + i).getBytes(StandardCharsets.UTF_8);

            // The "extract-then-expand" paradigm in action.
            byte[] prk = extract(userDefinedKeyBytes);
            byte[] okm = expand(prk, info);

            // Converting the raw bytes into a String using the Base62 encoding.
            subkeys[i] = toBase62(okm, 16);

        }

        return subkeys;
    }

    /**
     * This method implements the extract mechanism of the HKDF. In this
     * step, a pseudorandom key (prk) is "extracted" from a potentially
     * non-uniform, variable-entropy initial keying material (ikm). This key
     * can then be passed to the expand mechanism.
     *
     * @param ikm the input keying material
     * @return a pseudorandom key suitable for the expand mechanism of the HKDF
     * @throws NoSuchAlgorithmException in case the algorithm specified for
     * the Mac object is not available
     * @throws InvalidKeyException in case the key used to initialize the Mac
     * object is inappropriate
     */
    private static byte[] extract(byte[] ikm)
            throws NoSuchAlgorithmException, InvalidKeyException {
        Mac mac = Mac.getInstance(MAC_ALGORITHM);

        /*
         * In order for the HKDF to be deterministic (same subkeys derived
         * from the same user-defined key), a fixed salt must be used. As per
         * the RFC 5869, in this context the salt should be a string of zeros.
         */
        byte[] saltPlaceholder = new byte[mac.getMacLength()];
        Arrays.fill(saltPlaceholder, (byte) 0x00);

        mac.init(new SecretKeySpec(saltPlaceholder, MAC_ALGORITHM));

        // Returning the result of the HMAC to use in the expand mechanism.
        return mac.doFinal(ikm);
    }

    /**
     * This method implements the expand mechanism of the HKDF. This step
     * acts as a pseudorandom function keyed on the pseudorandom key obtained
     * by the extract mechanism; based on the context-bound info that are
     * used in the HMAC, a unique keying material of a desired length can be
     * output from the same pseudorandom key. It works by repeatedly calling
     * HMAC and using the pseudorandom key and info as messages, prepending
     * the previous hash block to the info field and appending with an
     * incrementing counter in each iteration so that T(n) = HMAC-HASH(PRK, T
     * (n-1) || info || n), for n > 0.
     *
     * @param prk the pseudorandom key obtained from the extract mechanism of
     *           the HKDF
     * @param info information that binds the derived key material to a
     *             specific round of encryption/ decryption
     * @return the output keying material
     * @throws NoSuchAlgorithmException in case the algorithm specified for
     * the Mac object is not available
     * @throws InvalidKeyException in case the key used to initialize the Mac
     * object is inappropriate
     */
    private static byte[] expand(byte[] prk, byte[] info)
            throws NoSuchAlgorithmException, InvalidKeyException {
        Mac mac = Mac.getInstance(MAC_ALGORITHM);
        mac.init(new SecretKeySpec(prk, MAC_ALGORITHM));

        // The desired length of the output keying material.
        int length = 16;

        byte[] result = new byte[length];
        // Starts as T(0); represents T(n-1).
        byte[] previous = new byte[0];
        // Tracks how many bytes have been written into the result buffer.
        int outPos = 0;
        int iterationCounter = 1;

        while (outPos < length) {
            mac.reset();
            // Prepending T(i-1) to the HMAC.
            mac.update(previous);
            // Appending the context-bound info.
            mac.update(info);
            // Appending the incrementing counter.
            mac.update((byte) iterationCounter);
            previous = mac.doFinal();
            /*
             * Use this value to only copy the desired number of bytes from
             * the HMAC result. Useful in the final iteration.
             */
            int copyLen = Math.min(previous.length, length - outPos);
            System.arraycopy(previous, 0, result, outPos, copyLen);

            outPos += copyLen;
            iterationCounter++;
        }

        return result;
    }

    /** Convert bytes to Base62 alphanumeric string */
    private static String toBase62(byte[] bytes, int length) {
        StringBuilder sb = new StringBuilder();
        int idx = 0;

        // Convert each byte to a Base62 character
        while (sb.length() < length) {
            int v = bytes[idx++] & 0xFF;
            sb.append(BASE62_ALPHABET[v % BASE62_ALPHABET.length]);
            if (idx >= bytes.length) idx = 0; // wrap if needed
        }

        return sb.toString();
    }

    public static void main(String[] args)
            throws NoSuchAlgorithmException, InvalidKeyException {
        String[] subkeys = generateSubkeys("this12is896a9key", 8);
        for (String subkey : subkeys) {
            System.out.println(subkey);
        }
    }

}
