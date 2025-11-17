import java.util.Random;

public class SubkeyGenerator {

    private static final String CHAR_POOL =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

    private static final Random RANDOM = new Random(3231);

    public static String[] getSubkeys(String masterKey, int rounds) {

        String[] subkeys = new String[rounds];

        for (int i = 0; i < rounds; i++) {

            StringBuilder subkeyBuilder = new StringBuilder();

            for (int j = 0; j < 16; j++) {
                subkeyBuilder.append(CHAR_POOL.charAt(RANDOM
                        .nextInt(CHAR_POOL.length())));
            }

            subkeys[i] = subkeyBuilder.toString();

        }

        return subkeys;

    }

}
