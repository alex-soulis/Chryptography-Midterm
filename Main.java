import java.util.ArrayList;
import java.util.Scanner;

/**
 * Main application class for the Password Vault System.
 *
 * <p>This class is responsible for:</p>
 * <ul>
 *   <li>Accepting user input</li>
 *   <li>Validating the encryption key</li>
 *   <li>Generating subkeys via SubkeyGenerator</li>
 *   <li>Creating the CustomCipher</li>
 *   <li>Managing encrypted records via VaultManager</li>
 * </ul>
 *
 * It provides a simple console menu interface for interacting
 * with the encrypted vault.
 */
public class Main {

    /**
     * Program entry point.
     *
     * @param args command-line arguments (not used)
     */
    public static void main(String[] args) {

        Scanner scanner = new Scanner(System.in);

        try {
            // Prompt user for master key
            System.out.print("Enter key (16 - 32 characters): ");
            String userKey = scanner.nextLine();

            // Validate key
            KeyManager keyManager = new KeyManager(userKey);

            // Generate subkeys externally
            SubkeyGenerator subkeyGenerator = new SubkeyGenerator(userKey);
            String[] roundKeys = subkeyGenerator.getRoundKeys();

            // Create cipher
            CustomCipher cipher = new CustomCipher(roundKeys);

            // Create vault manager
            VaultManager vaultManager = new VaultManager(cipher);

            // Create password generator
            PasswordGenerator passwordGenerator = new PasswordGenerator();

            int choice = -1;

            while (choice != 5) {

                System.out.println("\n==== PASSWORD VAULT MENU ====");
                System.out.println("1) Generate and store new password");
                System.out.println("2) View all records");
                System.out.println("3) Find record by label");
                System.out.println("4) Run benchmark");
                System.out.println("5) Exit");
                System.out.print("Choose: ");

                try {
                    choice = Integer.parseInt(scanner.nextLine());
                } catch (NumberFormatException e) {
                    choice = -1;
                }

                switch (choice) {

                    case 1:
                        System.out.print("Enter label: ");
                        String label = scanner.nextLine();

                        System.out.print("Password length (8–64): ");
                        int length;

                        try {
                            length = Integer.parseInt(scanner.nextLine());
                        } catch (Exception e) {
                            length = passwordGenerator.getPasswordLength();
                        }

                        String password = passwordGenerator.generatePassword(length);
                        vaultManager.storeRecord(label, password);
                        System.out.println("Record stored successfully.");
                        break;

                    case 2:
                        ArrayList<Record> records = vaultManager.retrieveRecords();
                        System.out.println("\n--- Vault Records ---");

                        if (records.isEmpty()) {
                            System.out.println("(No records found).");
                        } else {
                            for (Record r : records)
                                System.out.println(r);
                        }
                        break;

                    case 3:
                        System.out.print("Enter label to search: ");
                        String searchLabel = scanner.nextLine();
                        Record found = vaultManager.retrieveRecord(searchLabel);

                        if (found == null)
                            System.out.println("Record not found.");
                        else
                            System.out.println("Found: " + found);
                        break;

                    case 4:
                        Benchmark.run(cipher);
                        break;

                    case 5:
                        System.out.println("Exiting system...");
                        break;

                    default:
                        System.out.println("Invalid option.");
                }
            }

        } catch (Exception e) {
            System.out.println("System error: " + e.getMessage());
        }

        scanner.close();
    }
}
