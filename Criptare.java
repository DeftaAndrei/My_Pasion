import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;

public class Criptare {

    private static final int KEY_SIZE = 128; // 256 dacă Java suportă Unlimited Strength
    private static final int IV_SIZE = 12;
    private static final int TAG_SIZE = 128;
    private static final boolean DEBUG = true; // Activează modul de debug

    // Generează o cheie secretă AES
    public static SecretKey generateKey() throws Exception {
        if (DEBUG) System.out.println("Generare cheie AES de " + KEY_SIZE + " biți");
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(KEY_SIZE);
        SecretKey key = keyGen.generateKey();
        if (DEBUG) System.out.println("Cheie generată: " + Base64.getEncoder().encodeToString(key.getEncoded()));
        return key;
    }

    // Generează un IV aleator (nonce)
    public static byte[] generateIV() {
        if (DEBUG) System.out.println("Generare IV de " + IV_SIZE + " bytes");
        byte[] iv = new byte[IV_SIZE];
        new SecureRandom().nextBytes(iv);
        if (DEBUG) System.out.println("IV generat: " + Base64.getEncoder().encodeToString(iv));
        return iv;
    }

    // Criptare
    public static String encrypt(String plaintext, SecretKey key, byte[] iv) throws Exception {
        if (DEBUG) {
            System.out.println("Inițiere criptare:");
            System.out.println("Text de criptat: " + plaintext);
            System.out.println("Lungime text: " + plaintext.getBytes().length + " bytes");
        }
        
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(TAG_SIZE, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);

        if (DEBUG) System.out.println("Cipher inițializat în modul ENCRYPT");
        
        byte[] encrypted = cipher.doFinal(plaintext.getBytes());
        if (DEBUG) System.out.println("Text criptat: " + Base64.getEncoder().encodeToString(encrypted));
        
        byte[] encryptedWithIv = new byte[iv.length + encrypted.length];

        System.arraycopy(iv, 0, encryptedWithIv, 0, iv.length);
        System.arraycopy(encrypted, 0, encryptedWithIv, iv.length, encrypted.length);

        String result = Base64.getEncoder().encodeToString(encryptedWithIv);
        if (DEBUG) System.out.println("Rezultat final (IV + criptat, Base64): " + result);
        
        return result;
    }

    // Decriptare
    public static String decrypt(String encryptedText, SecretKey key) throws Exception {
        if (DEBUG) {
            System.out.println("Inițiere decriptare:");
            System.out.println("Text criptat (Base64): " + encryptedText);
        }
        
        byte[] encryptedWithIv = Base64.getDecoder().decode(encryptedText);
        if (DEBUG) System.out.println("Lungime date decodate: " + encryptedWithIv.length + " bytes");
        
        byte[] iv = new byte[IV_SIZE];
        byte[] encrypted = new byte[encryptedWithIv.length - IV_SIZE];

        System.arraycopy(encryptedWithIv, 0, iv, 0, IV_SIZE);
        System.arraycopy(encryptedWithIv, IV_SIZE, encrypted, 0, encrypted.length);

        if (DEBUG) {
            System.out.println("IV extras: " + Base64.getEncoder().encodeToString(iv));
            System.out.println("Date criptate extrase: " + Base64.getEncoder().encodeToString(encrypted));
        }

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(TAG_SIZE, iv);
        cipher.init(Cipher.DECRYPT_MODE, key, spec);

        if (DEBUG) System.out.println("Cipher inițializat în modul DECRYPT");

        try {
            byte[] decrypted = cipher.doFinal(encrypted);
            String result = new String(decrypted);
            if (DEBUG) System.out.println("Text decriptat: " + result);
            return result;
        } catch (Exception e) {
            if (DEBUG) {
                System.err.println("Eroare la decriptare: " + e.getMessage());
                e.printStackTrace();
            }
            throw e;
        }
    }

    // Salvează cheia într-un fișier
    public static void saveKey(SecretKey key, String filePath) throws IOException {
        try (FileOutputStream fos = new FileOutputStream(filePath)) {
            fos.write(key.getEncoded());
            if (DEBUG) System.out.println("Cheie salvată în: " + filePath);
        }
    }

    // Încarcă cheia dintr-un fișier
    public static SecretKey loadKey(String filePath) throws IOException {
        byte[] keyBytes = Files.readAllBytes(Paths.get(filePath));
        SecretKey key = new SecretKeySpec(keyBytes, "AES");
        if (DEBUG) System.out.println("Cheie încărcată din: " + filePath);
        return key;
    }

    // Criptează un fișier
    public static void encryptFile(String inputFile, String outputFile, SecretKey key) throws Exception {
        byte[] fileContent = Files.readAllBytes(Paths.get(inputFile));
        byte[] iv = generateIV();
        
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(TAG_SIZE, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);
        
        byte[] encrypted = cipher.doFinal(fileContent);
        byte[] encryptedWithIv = new byte[iv.length + encrypted.length];
        
        System.arraycopy(iv, 0, encryptedWithIv, 0, iv.length);
        System.arraycopy(encrypted, 0, encryptedWithIv, iv.length, encrypted.length);
        
        Files.write(Paths.get(outputFile), encryptedWithIv);
        if (DEBUG) System.out.println("Fișier criptat salvat în: " + outputFile);
    }

    // Decriptează un fișier
    public static void decryptFile(String inputFile, String outputFile, SecretKey key) throws Exception {
        byte[] encryptedWithIv = Files.readAllBytes(Paths.get(inputFile));
        
        byte[] iv = new byte[IV_SIZE];
        byte[] encrypted = new byte[encryptedWithIv.length - IV_SIZE];
        
        System.arraycopy(encryptedWithIv, 0, iv, 0, IV_SIZE);
        System.arraycopy(encryptedWithIv, IV_SIZE, encrypted, 0, encrypted.length);
        
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(TAG_SIZE, iv);
        cipher.init(Cipher.DECRYPT_MODE, key, spec);
        
        byte[] decrypted = cipher.doFinal(encrypted);
        Files.write(Paths.get(outputFile), decrypted);
        if (DEBUG) System.out.println("Fișier decriptat salvat în: " + outputFile);
    }

    // Măsoară performanța
    public static void benchmarkPerformance(int iterations, int dataSize) throws Exception {
        SecretKey key = generateKey();
        byte[] iv = generateIV();
        byte[] data = new byte[dataSize];
        new SecureRandom().nextBytes(data);
        String testData = Base64.getEncoder().encodeToString(data);
        
        System.out.println("Benchmark pentru " + iterations + " iterații cu date de " + dataSize + " bytes");
        
        // Benchmark criptare
        long startEncrypt = System.currentTimeMillis();
        for (int i = 0; i < iterations; i++) {
            encrypt(testData, key, iv);
        }
        long endEncrypt = System.currentTimeMillis();
        double encryptTime = (endEncrypt - startEncrypt) / 1000.0;
        System.out.println("Timp total criptare: " + encryptTime + " secunde");
        System.out.println("Timp mediu per criptare: " + (encryptTime / iterations) + " secunde");
        
        // Benchmark decriptare
        String encrypted = encrypt(testData, key, iv);
        long startDecrypt = System.currentTimeMillis();
        for (int i = 0; i < iterations; i++) {
            decrypt(encrypted, key);
        }
        long endDecrypt = System.currentTimeMillis();
        double decryptTime = (endDecrypt - startDecrypt) / 1000.0;
        System.out.println("Timp total decriptare: " + decryptTime + " secunde");
        System.out.println("Timp mediu per decriptare: " + (decryptTime / iterations) + " secunde");
    }

    // Exemplu de utilizare
    public static void main(String[] args) {
        try {
            System.out.println("=== Test de bază ===");
            String message = "Mesaj secret pentru testare";

            SecretKey key = generateKey();
            byte[] iv = generateIV();

            String encrypted = encrypt(message, key, iv);
            System.out.println("Criptat: " + encrypted);

            String decrypted = decrypt(encrypted, key);
            System.out.println("Decriptat: " + decrypted);
            
            System.out.println("\n=== Test salvare/încărcare cheie ===");
            String keyFile = "aes_key.bin";
            saveKey(key, keyFile);
            SecretKey loadedKey = loadKey(keyFile);
            
            String decryptedWithLoadedKey = decrypt(encrypted, loadedKey);
            System.out.println("Decriptat cu cheie încărcată: " + decryptedWithLoadedKey);
            
            System.out.println("\n=== Benchmark performanță ===");
            benchmarkPerformance(100, 1024);
            
            System.out.println("\nToate testele au fost finalizate cu succes!");
        } catch (Exception e) {
            System.err.println("Eroare: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
