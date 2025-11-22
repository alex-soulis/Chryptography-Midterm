import java.io.*;
import java.util.ArrayList;
import java.util.Scanner;

/**
 * This class can be used to manage the encrypted file where all the
 * passwords and their labels are stored. The records are expected to have
 * the following form: the label (encrypted), followed by whitespace
 * character, and then the password (encrypted). To follow this format, the
 * auxiliary {@link Record} class is used. The class uses the
 * {@link CustomCipher} class to encrypt plaintext to ciphertext and decrypt
 * ciphertext to plaintext respectively. It also uses a validation string (a
 * predefined string at the start of the file) that can be used to ensure the
 * user has entered the correct key for the specific vault file.
 *
 * @see CustomCipher
 * @see Record
 */
public class VaultManager {

    public static final File VAULT_FILE = new File("vault.txt");

    private static final String VALIDATION_STRING = "VALID_KEY";

    private final CustomCipher cipher;

    /**
     * This constructor initializes a VaultManager object by setting the
     * cipher object. It also checks if the vault file exists, and if it
     * doesn't, it creates one and appends the validation string at the start
     * of the file.
     *
     * @param cipherConstr the cipher to be used to encrypt and decrypt the
     *                     vault file
     * @throws IllegalArgumentException in case the passed cipher is null
     */
    public VaultManager(CustomCipher cipherConstr)
            throws IllegalArgumentException {
        if (cipherConstr == null) {
            throw new IllegalArgumentException("Passed cipher is null.");
        } else {
            cipher = cipherConstr;
        }

        try {
            if (VAULT_FILE.createNewFile()) {
                try (FileWriter fileWriter = new FileWriter(VAULT_FILE)) {
                    fileWriter.write(cipher.encrypt(VALIDATION_STRING)
                            + "\n");
                }
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * This method can be used to validate the user-defined key. The cipher
     * (initialized with the user-defined key) is used to decrypt the
     * validation string, which is then compared to the predefined validation
     * string value.
     *
     * @return true, if the user-define key is correct; false, otherwise
     */
    public boolean validateKey()  {
        try {
            Scanner fileScanner = new Scanner(VAULT_FILE);
            String firstLine =  fileScanner.nextLine();
            return cipher.decrypt(firstLine).equals(VALIDATION_STRING);
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Encrypts and stores a new record in the vault file.
     *
     * @param label the label of the password
     * @param password the password corresponding to the label
     */
    public void storeRecord(String label, String password) {
        try (FileWriter fileWriter = new FileWriter(VAULT_FILE, true)){
            fileWriter.write(cipher.encrypt(label) + " "
                    + cipher.encrypt(password) + "\n");
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Encrypts and stores an {@link ArrayList} of records (implemented as
     * {@link Record} objects).
     *
     * @param records an ArrayList of Record objects
     */
    public void storeRecords(ArrayList<Record> records) {
        try (BufferedWriter bufferedWriter =
                     new BufferedWriter(new FileWriter(VAULT_FILE,true))) {
            for (Record r : records) {
                bufferedWriter.write(cipher.encrypt(r.getLabel()) + " "
                        + cipher.encrypt(r.getPassword()));
                bufferedWriter.newLine();
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Retrieves and decrypts all records and returns them as an
     * {@link ArrayList} of {@link Record} objects.
     *
     * @return an ArrayList of Record objects
     */
    public ArrayList<Record> retrieveRecords() {
        try {
            ArrayList<Record> records = new ArrayList<>();
            BufferedReader bufferedReader = new BufferedReader(
                    new FileReader(VAULT_FILE));
            String line;
            // First line stores the validation string.
            bufferedReader.readLine();
            while ((line = bufferedReader.readLine()) != null) {
                String[] tokens = line.split(" ");
                records.add(new Record(cipher.decrypt(tokens[0]),
                        cipher.decrypt(tokens[1])));
            }
            return records;
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Retrieves and decrypts the record that corresponds to the passed
     * label, and returns it as an {@link Record} object.
     *
     * @param label the label of the requested record
     * @return the Record that corresponding to the passed label
     */
    public Record retrieveRecord(String label) {
        try {
            BufferedReader bufferedReader =
                    new BufferedReader(new FileReader(VAULT_FILE));
            String line;
            // First line stores the validation string.
            bufferedReader.readLine();
            while ((line = bufferedReader.readLine()) != null) {
                String[] tokens = line.split(" ");
                if (cipher.decrypt(tokens[0]).equalsIgnoreCase(label)) {
                    return new Record(cipher.decrypt(tokens[0]),
                            cipher.decrypt(tokens[1]));
                }
            }
            return null;
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

}
