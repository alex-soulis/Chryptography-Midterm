public class Benchmark {

    /**
     * This class can be used to roughly evaluate the time
     * of the encryption/decryption algorithm by measuring how
     * time grows as the number of processed passwords increases.
     */
    public static void run(CustomCipher cipher) {

        String sample = "email SamplePassword123!";

        System.out.println("---- Encryption/Decryption Benchmark ----");
        System.out.println("Count\tTime (ms)");

        for (int count = 10; count <= 1000; count += 100) {

            long start = System.currentTimeMillis();

            for (int i = 0; i < count; i++) {
                String c = cipher.encrypt(sample);
                String p = cipher.decrypt(c);
            }

            long end = System.currentTimeMillis();
            long duration = end - start;

            System.out.println(count + "\t" + duration);
        }
    }
}
