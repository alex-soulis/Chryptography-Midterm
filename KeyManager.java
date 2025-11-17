/**
 * This class can be used to manage the user defined key, as well as the
 * subkeys used in the encryption/ decryption algorithm.
 */
public class KeyManager {

    private final static int MIN_KEY_LENGTH = 16;
    private final static int MAX_KEY_LENGTH = 32;

    /**
     * The key defined by the user.
     */
    private final String userDefinedKey;

    /**
     * The current subkey. Changes each round.
     */
    private String currentRoundKey;

    /**
     * A counter used to keep track of the rounds of encryption/ decryption.
     */
    private int roundCounter;

    /**
     * Constructs a key manager object.
     *
     * @param key the user-defined key
     * @throws IllegalAccessException in case the key is
     */
    public KeyManager(String key) throws IllegalAccessException {
        if (key.length() < MIN_KEY_LENGTH) {
            throw new IllegalAccessException("Key is too short. Provide a " +
                    "key that is more than or equal to 16 characters.");
        } else if (key.length() > MAX_KEY_LENGTH) {
            throw new IllegalArgumentException("Key is too long. Provide a " +
                    "key that is less than or equal to 32 characters.");
        }

        userDefinedKey = key;
        currentRoundKey = "";
        roundCounter = 0;
    }

    /**
     * Use this method to get the current round key.
     *
     * @return the current round key
     * @throws IllegalStateException in case no current round key exists
     */
    public String getCurrentRoundKey() throws IllegalStateException{
        if (currentRoundKey.equals("")) {
            throw new IllegalStateException("Current round key is empty.");
        }
        return currentRoundKey;
    }

    /**
     * Use this method to calculate the next round key. After this method is
     * called, the current round key value is changed to the value of the round
     * key calculated in this method.
     *
     * @return the next round key
     */
    public String nextRoundKey() {
        /*
         * At this point, the next round key will be calculated and assigned
         * to the currentRoundKey variable.
         */
        //TODO add functionality
        roundCounter++;
        return currentRoundKey;
    }

}