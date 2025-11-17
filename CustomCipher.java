/**
 * This class implements a simple custom symmetric cipher.
 * - Uses a user-defined key (16–32 characters).
 * - Derives 4 round subkeys by cyclic rotation of the main key.
 * - Each encryption round applies:
 * 1) substitution (char-wise, based on the subkey)
 * 2) permutation (string reversal)
 * - Decryption applies the inverse operations in reverse round order.
 */
public class CustomCipher {

    private final String mainKey;
    private final String[] roundKeys;

    /**
     * Constructs a cipher with the given user key.
     *
     * @param userKey the user-defined key (should be 16–32 characters)
     */
    public CustomCipher(String userKey) {
        this.mainKey = userKey;
        this.roundKeys = new String[4];
        generateRoundKeys();
    }

    /**
     * Generates 4 round keys of the same length as the main key,
     * using cyclic rotations.
     */
    private void generateRoundKeys() {
        int len = mainKey.length();
        for (int i = 0; i < 4; i++) {
            int shift = ((i + 1) * 3) % len; // different shift per round
            roundKeys[i] = mainKey.substring(shift) + mainKey.substring(0, shift);
        }
    }

    /**
     * Encrypts a plaintext string using 4 rounds of
     * substitution + permutation.
     *
     * @param plaintext the input text
     * @return the encrypted ciphertext
     */
    public String encrypt(String plaintext) {
        String result = plaintext;
        for (int round = 0; round < 4; round++) {
            result = substitution(result, roundKeys[round]);
            result = permutation(result);
        }
        return result;
    }

    /**
     * Decrypts a ciphertext string using 4 rounds of
     * inverse permutation + inverse substitution.
     *
     * @param ciphertext the encrypted text
     * @return the decrypted plaintext
     */
    public String decrypt(String ciphertext) {
        String result = ciphertext;
        for (int round = 3; round >= 0; round--) {
            result = reversePermutation(result);
            result = reverseSubstitution(result, roundKeys[round]);
        }
        return result;
    }

    // ---------- Substitution and its inverse ----------

    private String substitution(String text, String key) {
        StringBuilder sb = new StringBuilder();
        int keyLen = key.length();
        for (int i = 0; i < text.length(); i++) {
            char ptChar = text.charAt(i);
            char kChar = key.charAt(i % keyLen);
            char ctChar = (char) (ptChar + kChar);
            sb.append(ctChar);
        }
        return sb.toString();
    }

    private String reverseSubstitution(String text, String key) {
        StringBuilder sb = new StringBuilder();
        int keyLen = key.length();
        for (int i = 0; i < text.length(); i++) {
            char ctChar = text.charAt(i);
            char kChar = key.charAt(i % keyLen);
            char ptChar = (char) (ctChar - kChar);
            sb.append(ptChar);
        }
        return sb.toString();
    }

    // ---------- Permutation and its inverse (reverse) ----------

    private String permutation(String text) {
        return new StringBuilder(text).reverse().toString();
    }

    private String reversePermutation(String text) {
        return new StringBuilder(text).reverse().toString();
    }
}
