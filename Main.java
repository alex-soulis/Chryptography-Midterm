import java.util.ArrayList;
import java.util.Scanner;

public class Main {

    public static void main(String[] args) {

        Scanner scanner = new Scanner(System.in);

        try {
            // 1. Ask user for main key
            System.out.print("Enter key (16–32 characters): ");
            String userKey = scanner.nextLine();

            // 2. Validate key using KeyManager (throws if invalid)
            KeyManager keyManager = new KeyManager(userKey);

            // 3. Generate round keys using your teammate's class
            //    (SubkeyGenerator must be implemented in a separate file)
            SubkeyGenerator subkeyGenerator = new SubkeyGenerator(userKey);
            String[] roundKeys = subkeyGenerator.getRoundKeys();

            // 4. Create cipher with round keys
            CustomCipher cipher = new CustomCipher(roundKeys);

            // 5. Create VaultManager using the cipher (handles marker + vault file)
            VaultManager vaultManager = new VaultManager(cipher);

            // 6. Password generator
            PasswordGenerator passwordGenerator = new PasswordGenerator();

            int choice = -1;
            while (choice != 5) {
                System.out.println("\n==== PASSWORD VAULT MENU ====");
                System.out.println("1) Generate and store new password");
                System.out.println("2) View all records (decrypted)");
                System.out.println("3) Find record by label");
                System.out.println("4) Run encryption benchmark");
                System.out.println("5) Exit");
                System.out.print("Choose: ");

                try {
                    choice = Integer.parseInt(scanner.nextLine());
                } catch (NumberFormatException e) {
                    choice = -1;
                }

                switch (choice) {
                    case 1:
                        // Generate + store password
                        System.out.print("Enter label: ");
                        String label = scanner.nextLine();

                        System.out.print("Enter password length (8–64): ");
                        int length;
                        try {
                            length = Integer.parseInt(scanner.nextLine());
                        } catch (NumberFormatException e) {
                            System.out.println("Invalid length. Using default length.");
                            length = passwordGenerator.getPasswordLength();
                        }

                        String password;
                        try {
                            password = passwordGenerator.generatePassword(length);
                        } catch (IllegalArgumentException e) {
                            System.out.println(e.getMessage());
                            System.out.println("Using default length instead.");
                            password = passwordGenerator.generatePassword();
                        }

                        vaultManager.storeRecord(label, password);
                        System.out.println("Stored record: " + label + " (password generated and encrypted).");
                        break;

                    case 2:
                        // View all records
                        ArrayList<Record> records = vaultManager.retrieveRecords();
                        System.out.println("\n-- Decrypted Vault Records --");
                        if (records.isEmpty()) {
                            System.out.println("(No records found or wrong key.)");
                        } else {
                            for (Record r : records) {
                                System.out.println(r);
                            }
                        }
                        break;

                    case 3:
                        // Find by label
                        System.out.print("Enter label to search: ");
                        String searchLabel = scanner.nextLine();
                        Record found = vaultManager.retrieveRecord(searchLabel);
                        if (found == null) {
                            System.out.println("No record found with label: " + searchLabel);
                        } else {
                            System.out.println("Found: " + found);
                        }
                        break;

                    case 4:
                        // Run benchmark (time vs number of encrypt/decrypt operations)
                        Benchmark.run(cipher);
                        break;

                    case 5:
                        System.out.println("Exiting...");
                        break;

                    default:
                        System.out.println("Invalid choice. Try again.");
                        break;
                }
            }

        } catch (Exception e) {
            System.out.println("Error: " + e.getMessage());
        }

        scanner.close();
    }
}
