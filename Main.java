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

        System.out.println("""
================================================================================
||                              Password Manager                              ||
================================================================================
""");

        System.out.println("""
    Welcome! This program can be used to create and store passwords. The
passwords are stored in an encrypted form so that only your key can decrypt
them.
""");

        try {

            CustomCipher cipher;
            VaultManager vaultManager;

            if (!VaultManager.VAULT_FILE.exists()) {

                System.out.println("""
It seems like you are using this program for the first time. Please enter a key
of your choice that is 16 characters long and consists of letters (lower and/or
upper case) and numbers (symbols are not allowed).
""");

                String[] roundKeys;
                while (true){
                    System.out.print("Key: ");
                    try {
                        String userKey = scanner.nextLine();
                        roundKeys = SubkeyGenerator.generateSubkeys(userKey, 8);
                        break;
                    } catch (IllegalArgumentException exc) {
                        if (exc.getMessage().equals("Invalid key length")) {
                            System.out.println("The key must be 16 characters! "
                                    + "Please try again.");
                        } else if (exc.getMessage().equals("Invalid key "
                                + "characters")) {
                            System.out.println("""
The key must only contain letters (lower and/or upper case) and numbers (symbols
are not allowed). Please try again.""");
                        }
                    }
                }

                cipher = new CustomCipher(roundKeys);
                vaultManager = new VaultManager(cipher);

            } else {

                while (true) {

                    System.out.print("Key: ");
                    String userKey = scanner.nextLine();

                    String[] roundKeys;
                    try {
                        roundKeys = SubkeyGenerator
                                .generateSubkeys(userKey, 8);
                    } catch (IllegalArgumentException exc) {
                        if (exc.getMessage().equals("Invalid key length")) {
                            System.out.println("The key must be 16 characters! "
                                    + "Please try again.");
                        } else if (exc.getMessage().equals("Invalid key "
                                + "characters")) {
                            System.out.println("""
The key must only contain letters (lower and/or upper case) and numbers (symbols
are not allowed). Please try again.""");
                        }
                        continue;
                    }


                    cipher = new CustomCipher(roundKeys);
                    vaultManager = new VaultManager(cipher);

                    // Validating user-defined key
                    if (vaultManager.validateKey()) {
                        break;
                    } else {
                        System.out.println("Invalid key! Please try again.");
                    }

                }

            }

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
                        while (true) {
                            System.out.print("Enter label: ");
                            String label = scanner.nextLine();

                            System.out.print("Password length (8–64): ");
                            int length;

                            try {
                                length = Integer.parseInt(scanner.nextLine());
                            } catch (Exception e) {
                                length = PasswordGenerator
                                        .DEFAULT_PASSWORD_LENGTH;
                                System.out.println("Invalid length! The default"
                                        + " password length was used instead.");
                            }

                            String password = passwordGenerator
                                    .generatePassword(length);
                            try {
                                vaultManager.storeRecord(label, password);
                                break;
                            } catch (IllegalArgumentException exc) {
                                System.out.println("A record with that label " +
                                        "already exists. Please try again.");
                            }
                        }
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
