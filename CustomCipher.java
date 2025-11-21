/**
 * Custom symmetric cipher based on an 8-round
 * Substitution–Permutation Network (SPN).
 *
 * IMPORTANT:
 * - This version does NOT generate subkeys internally.
 * - Round keys must be provided by an external class.
 * - Each round key must have the same length.
 *
 * Rounds:
 *   1) Substitution with round key
 *   2) Block-wise P-box permutation
 */
public class CustomCipher {

    private static final int ROUNDS = 8;

    // ----------------- ROUND KEYS RECEIVED EXTERNALLY -----------------

    private final String[] roundKeys;  // must be length = 8

    // ----------------- P-BOX -----------------

    private static final int BLOCK_SIZE = 8;

    private static final int[] PBOX = {2, 5, 1, 7, 4, 0, 3, 6};
    private static final int[] PBOX_INV = new int[BLOCK_SIZE];

    static {
        for (int i = 0; i < BLOCK_SIZE; i++) {
            PBOX_INV[PBOX[i]] = i;
        }
    }

    /**
     * Constructor: receives already-prepared round keys.
     *
     * @param roundKeys an array of 8 subkeys prepared externally
     */
    public CustomCipher(String[] roundKeys) {
        if (roundKeys == null || roundKeys.length != ROUNDS) {
            throw new IllegalArgumentException("Exactly 8 round keys required.");
        }
        this.roundKeys = roundKeys;
    }

    // ----------------- ENCRYPTION -----------------

    public String encrypt(String plaintext) {
        String result = plaintext;
        for (int round = 0; round < ROUNDS; round++) {
            result = substitution(result, roundKeys[round]);
            result = permutation(result);
        }
        return result;
    }

    // ----------------- DECRYPTION -----------------

    public String decrypt(String ciphertext) {
        String result = ciphertext;
        for (int round = ROUNDS - 1; round >= 0; round--) {
            result = reversePermutation(result);
            result = reverseSubstitution(result, roundKeys[round]);
        }
        return result;
    }

    // ----------------- SUBSTITUTION -----------------

    private String substitution(String text, String key) {
        StringBuilder sb = new StringBuilder();
        int keyLen = key.length();

        for (int i = 0; i < text.length(); i++) {
            char t = text.charAt(i);
            char k = key.charAt(i % keyLen);
            sb.append((char) (t + k));
        }
        return sb.toString();
    }

    private String reverseSubstitution(String text, String key) {
        StringBuilder sb = new StringBuilder();
        int keyLen = key.length();

        for (int i = 0; i < text.length(); i++) {
            char t = text.charAt(i);
            char k = key.charAt(i % keyLen);
            sb.append((char) (t - k));
        }
        return sb.toString();
    }

    // ----------------- P-BOX -----------------

    private String permutation(String text) {
        char[] in = text.toCharArray();
        char[] out = new char[in.length];

        int len = in.length;
        int offset = 0;

        while (offset < len) {
            int blockLen = Math.min(BLOCK_SIZE, len - offset);

            if (blockLen < BLOCK_SIZE) {
                for (int j = 0; j < blockLen; j++)
                    out[offset + j] = in[offset + j];
            } else {
                for (int j = 0; j < BLOCK_SIZE; j++)
                    out[offset + PBOX[j]] = in[offset + j];
            }

            offset += blockLen;
        }

        return new String(out);
    }

    private String reversePermutation(String text) {
        char[] in = text.toCharArray();
        char[] out = new char[in.length];

        int len = in.length;
        int offset = 0;

        while (offset < len) {
            int blockLen = Math.min(BLOCK_SIZE, len - offset);

            if (blockLen < BLOCK_SIZE) {
                for (int j = 0; j < blockLen; j++)
                    out[offset + j] = in[offset + j];
            } else {
                for (int j = 0; j < BLOCK_SIZE; j++)
                    out[offset + PBOX_INV[j]] = in[offset + j];
            }

            offset += blockLen;
        }

        return new String(out);
    }
}
