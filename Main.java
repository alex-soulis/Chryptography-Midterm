import java.util.ArrayList;
import java.util.Scanner;

public class Main {

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        try {
            // 1. Read user key
            System.out.print("Enter key (16 - 32 characters): ");
            String key = scanner.nextLine();

            // Validate key using KeyManager (throws if invalid)
            KeyManager keyManager = new KeyManager(key);

            // 2. Initialize cipher and vault
            CustomCipher cipher = new CustomCipher(key);
            VaultManager vaultManager = new VaultManager(cipher);

            // 3. Password generator
            PasswordGenerator passwordGenerator = new PasswordGenerator();

            int choice = -1;
            while (choice != 4) {
                System.out.println("\n==== MENU ====");
                System.out.println("1) Generate and store new password");
                System.out.println("2) View all records (decrypted)");
                System.out.println("3) Run encryption benchmark");
                System.out.println("4) Exit");
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

                        System.out.print("Enter password length (8–64): ");
                        int length;
                        try {
                            length = Integer.parseInt(scanner.nextLine());
                        } catch (NumberFormatException e) {
                            System.out.println("Invalid length. Using default.");
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
                        ArrayList<Record> records = vaultManager.retrieveRecords();
                        System.out.println("\n-- Decrypted Vault Records --");
                        for (Record r : records) {
                            System.out.println(r);
                        }
                        break;

                    case 3:
                        Benchmark.run(cipher);
                        break;

                    case 4:
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
