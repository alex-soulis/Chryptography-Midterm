import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.BufferedWriter;
import java.io.BufferedReader;
import java.util.ArrayList;
import java.io.FileReader;

/**
 * This class can be used to manage the encrypted file where all the
 * passwords and their labels are stored. The records are expected to have
 * the following form: the label (encrypted), followed by whitespace
 * character, and then the password (encrypted).
 */
public class VaultManager {

    private final File VAULT_FILE = new File("vault.txt");

    private final CustomCipher cipher;
    
    public VaultManager(CustomCipher cipher) {
        this.cipher = cipher;
    }

    /**
     * Encrypts and stores a new record in the vault file.
     *
     * @param label the label of the password
     * @param password the password corresponding to the label
     */
    public void storeRecord(String label, String password) {
        try (FileWriter fileWriter = new FileWriter(VAULT_FILE, true)){
            //TODO encrypt the data before writing to the file
            fileWriter.write(label + " " + password + "\n");
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
                //TODO encrypt the data before writing to the file
                bufferedWriter.write(r.getLabel() + " " + r.getPassword());
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
            while ((line = bufferedReader.readLine()) != null) {
                String[] tokens = line.split(" ");
                //TODO decrypt the data before returning them
                records.add(new Record(tokens[0], tokens[1]));
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
            while ((line = bufferedReader.readLine()) != null) {
                String[] tokens = line.split(" ");
                if (tokens[0].equals(label)) {
                    //TODO decrypt the data before returning them
                    return new Record(tokens[0], tokens[1]);
                }
            }
            return null;
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

}