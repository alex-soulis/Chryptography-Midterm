import java.security.SecureRandom;

/**
 * This class can be used to generate strong random passwords of
 * user-defined length, consisting of letters (both lower and uppercase),
 * numbers, and symbols. The length of the passwords must be within certain
 * limits, as recommended by the latest National Institute Standards and
 * Technology (NIST) guidelines
 * (<a href="https://pages.nist.gov/800-63-4/sp800-63b.html">SP 800-63B</a>).
 * To increase the strength of the generated passwords, the {@link SecureRandom}
 * class is used wherever a pseudorandom number generator is required.
 *
 * @see SecureRandom
 */
public class PasswordGenerator {

    private static final String LETTERS_LOWER_CASE =
            "abcdefghijklmnopqrstuvwxyz";
    private static final String LETTERS_UPPER_CASE =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private static final String NUMBERS = "0123456789";
    private static final String SYMBOLS = "!@#$%^&*()-=_+";

    public static final int MIN_PASSWORD_LENGTH = 8;
    public static final int DEFAULT_PASSWORD_LENGTH = 16;
    public static final int MAX_PASSWORD_LENGTH = 64;

    // All the characters used to generate passwords.
    private final String characterPool;

    private int passwordLength;

    /**
     * Constructs a password generator object by defining the character pool
     * and setting the password length to the default length.
     */
    public PasswordGenerator() {
            characterPool =
                    LETTERS_LOWER_CASE + LETTERS_UPPER_CASE + NUMBERS + SYMBOLS;
            passwordLength = DEFAULT_PASSWORD_LENGTH;
    }

    /**
     * Sets the password length to a user-defined value.
     *
     * @param userDefinedLength the user-defined length
     * @throws IllegalArgumentException in case the passed length is shorter
     * than the recommended minimum password length, or longer than the maximum
     * password length
     */
    public void setPasswordLength(int userDefinedLength)
            throws IllegalArgumentException {
        if (userDefinedLength < MIN_PASSWORD_LENGTH) {
            throw new IllegalArgumentException("Password length must be at " +
                    "least " +  MIN_PASSWORD_LENGTH);
        } else if (userDefinedLength > MAX_PASSWORD_LENGTH) {
            throw new IllegalArgumentException("Password length must be at " +
                    "most " + MAX_PASSWORD_LENGTH);
        }

        passwordLength = userDefinedLength;
    }

//    /**
//     * Gets the current password length.
//     *
//     * @return the current password length
//     */
//    public int getPasswordLength() {
//        return passwordLength;
//    }

    /**
     * Generates a strong random password consisting of letters (lower and
     * upper case), numbers, and symbols. The length of the password is
     * defined by the current password length value.
     *
     * @return a strong random password
     */
    public String generatePassword() {
        SecureRandom randomNumberGenerator = new SecureRandom();
        StringBuilder stringBuilder = new StringBuilder();
        for (int i = 0; i < passwordLength; i++) {
            stringBuilder.append(characterPool.charAt(randomNumberGenerator
                    .nextInt(characterPool.length())));
        }
        return stringBuilder.toString();
    }

    /**
     * Generates a strong random password of user-defined length consisting of
     * letters (lower and upper case), numbers, and symbols. The passed
     * length is validated using the setPasswordLength() method.
     *
     * @param userDefinedLength the user-defined length
     * @return a strong random password
     * @throws IllegalArgumentException in case the passed length is shorter
     * than the recommended minimum password length, or longer than the maximum
     * password length
     */
    public String generatePassword(int userDefinedLength)
            throws IllegalArgumentException {
        setPasswordLength(userDefinedLength);
        SecureRandom randomNumberGenerator = new SecureRandom();
        StringBuilder stringBuilder = new StringBuilder();
        for (int i = 0; i < userDefinedLength; i++) {
            stringBuilder.append(characterPool.charAt(randomNumberGenerator
                    .nextInt(characterPool.length())));
        }
        return stringBuilder.toString();
    }

}