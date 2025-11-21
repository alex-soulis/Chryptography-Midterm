import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.BufferedWriter;
import java.io.BufferedReader;
import java.util.ArrayList;
import java.io.FileReader;

/**
 * This class manages the encrypted vault file where all the
 * passwords and their labels are stored.
 *
 * Record format (plaintext before encryption):
 *     <label> <password>
 *
 * First line of the vault file is an encrypted validation marker ("VALID")
 * used to check whether the user's key is correct.
 */
public class VaultManager {

    private final File VAULT_FILE = new File("vault.txt");

    // Cipher used for encrypting/decrypting
    private final CustomCipher cipher;

    // Validation marker
    private static final String MARKER = "VALID";

    // Constructor used in your app
    public VaultManager(CustomCipher cipher) {
        this.cipher = cipher;
    }

    /**
     * Writes the encrypted validation marker ONLY if the file is empty.
     */
    private void writeMarkerIfEmpty() throws IOException {
        if (VAULT_FILE.length() == 0) {
            try (FileWriter writer = new FileWriter(VAULT_FILE, true)) {
                String encryptedMarker = cipher.encrypt(MARKER);
                writer.write(encryptedMarker + "\n");
            }
        }
    }

    /**
     * Reads the validation marker and checks if the key is correct.
     * Returns true if valid, false if key is wrong.
     */
    private boolean validateKey(BufferedReader reader) throws IOException {
        String firstLine = reader.readLine();
        if (firstLine == null) return false;

        String decrypted = cipher.decrypt(firstLine);
        return decrypted.equals(MARKER);
    }

    /**
     * Encrypts and stores a new record in the vault file.
     */
    public void storeRecord(String label, String password) {
        if (cipher == null) {
            throw new IllegalStateException("Cipher is not initialized in VaultManager.");
        }
        try {
            writeMarkerIfEmpty(); // ensure marker exists

            try (FileWriter fileWriter = new FileWriter(VAULT_FILE, true)) {
                String plainLine = label + " " + password;
                String encryptedLine = cipher.encrypt(plainLine);
                fileWriter.write(encryptedLine + "\n");
            }

        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Encrypts and stores multiple records.
     */
    public void storeRecords(ArrayList<Record> records) {
        if (cipher == null) {
            throw new IllegalStateException("Cipher is not initialized in VaultManager.");
        }
        try {
            writeMarkerIfEmpty(); // ensure marker exists

            try (BufferedWriter bufferedWriter =
                         new BufferedWriter(new FileWriter(VAULT_FILE,true))) {
                for (Record r : records) {
                    String plainLine = r.getLabel() + " " + r.getPassword();
                    String encryptedLine = cipher.encrypt(plainLine);
                    bufferedWriter.write(encryptedLine);
                    bufferedWriter.newLine();
                }
            }

        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Retrieves and decrypts all records from the vault.
     */
    public ArrayList<Record> retrieveRecords() {
        if (cipher == null) {
            throw new IllegalStateException("Cipher is not initialized in VaultManager.");
        }
        try {
            ArrayList<Record> records = new ArrayList<>();
            BufferedReader bufferedReader = new BufferedReader(
                    new FileReader(VAULT_FILE));

            // Validate key first
            if (!validateKey(bufferedReader)) {
                System.out.println("ERROR: Incorrect key. Cannot decrypt vault.");
                return records; // return empty
            }

            // Process remaining lines (records)
            String line;
            while ((line = bufferedReader.readLine()) != null) {
                String decryptedLine = cipher.decrypt(line);

                int spaceIndex = decryptedLine.indexOf(' ');
                if (spaceIndex == -1) continue;

                String label = decryptedLine.substring(0, spaceIndex);
                String password = decryptedLine.substring(spaceIndex + 1);
                records.add(new Record(label, password));
            }

            return records;

        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Retrieves one record by label.
     */
    public Record retrieveRecord(String label) {
        if (cipher == null) {
            throw new IllegalStateException("Cipher is not initialized in VaultManager.");
        }
        try {
            BufferedReader bufferedReader =
                    new BufferedReader(new FileReader(VAULT_FILE));

            // Validate key
            if (!validateKey(bufferedReader)) {
                System.out.println("ERROR: Incorrect key. Cannot decrypt vault.");
                return null;
            }

            // Search through records
            String line;
            while ((line = bufferedReader.readLine()) != null) {
                String decryptedLine = cipher.decrypt(line);

                int spaceIndex = decryptedLine.indexOf(' ');
                if (spaceIndex == -1) continue;

                String recordLabel = decryptedLine.substring(0, spaceIndex);
                String recordPassword = decryptedLine.substring(spaceIndex + 1);

                if (recordLabel.equals(label)) {
                    return new Record(recordLabel, recordPassword);
                }
            }

            return null;

        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

}
