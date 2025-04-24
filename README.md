# My_Pasion 
# Documentație Criptare.java

## Descriere
Acest fișier implementează un sistem de criptare AES (Advanced Encryption Standard) în Java, folosind modul GCM (Galois/Counter Mode) pentru securitate sporită. Codul este scris cu debugging activat pentru a urmări pașii de criptare/decriptare.

## Constante Importante
```java
private static final int KEY_SIZE = 128;    // Dimensiunea cheii AES
private static final int IV_SIZE = 12;      // Dimensiunea vectorului de inițializare
private static final int TAG_SIZE = 128;    // Dimensiunea tag-ului de autentificare
private static final boolean DEBUG = true;   // Mod debug activat
```

## Funcționalități Implementate

### 1. Generare Cheie AES (`generateKey()`)
```java
public static SecretKey generateKey() throws Exception
```
- Folosește `KeyGenerator.getInstance("AES")`
- Inițializează cu dimensiunea de 128 biți
- Returnează o cheie secretă AES
- Afișează cheia generată în format Base64 când DEBUG este activ

### 2. Generare Vector de Inițializare (`generateIV()`)
```java
public static byte[] generateIV()
```
- Creează un IV de 12 bytes
- Folosește `SecureRandom` pentru generare aleatorie sigură
- Returnează IV-ul ca array de bytes
- Afișează IV-ul în format Base64 când DEBUG este activ

### 3. Criptare Text (`encrypt()`)
```java
public static String encrypt(String plaintext, SecretKey key, byte[] iv)
```
- Primește: text plain, cheie AES și IV
- Folosește AES/GCM/NoPadding
- Pași:
  1. Creează un obiect Cipher
  2. Inițializează cu modul ENCRYPT
  3. Criptează textul
  4. Combină IV-ul cu textul criptat
  5. Encodează rezultatul în Base64
- Returnează string-ul criptat în format Base64

### 4. Decriptare Text (`decrypt()`)
```java
public static String decrypt(String encryptedText, SecretKey key)
```
- Primește: text criptat (Base64) și cheie
- Pași:
  1. Decodează din Base64
  2. Extrage IV-ul (primii 12 bytes)
  3. Extrage datele criptate
  4. Decriptează folosind AES/GCM
- Returnează textul original

### 5. Salvare Cheie (`saveKey()`)
```java
public static void saveKey(SecretKey key, String filePath)
```
- Salvează cheia AES într-un fișier binar
- Folosește `FileOutputStream`
- Salvează bytes-ii cheii direct în fișier

### 6. Încărcare Cheie (`loadKey()`)
```java
public static SecretKey loadKey(String filePath)
```
- Citește cheia din fișier folosind `Files.readAllBytes()`
- Creează un nou `SecretKeySpec` din bytes-ii citiți
- Returnează cheia AES reconstruită

### 7. Criptare Fișier (`encryptFile()`)
```java
public static void encryptFile(String inputFile, String outputFile, SecretKey key)
```
- Citește conținutul fișierului
- Generează IV nou
- Criptează conținutul
- Salvează IV + date criptate în fișierul de output

### 8. Decriptare Fișier (`decryptFile()`)
```java
public static void decryptFile(String inputFile, String outputFile, SecretKey key)
```
- Citește fișierul criptat
- Extrage IV-ul și datele criptate
- Decriptează datele
- Salvează rezultatul în fișierul de output

### 9. Testare Performanță (`benchmarkPerformance()`)
```java
public static void benchmarkPerformance(int iterations, int dataSize)
```
- Măsoară timpul pentru operații de criptare/decriptare
- Parametri configurabili:
  - Număr de iterații
  - Dimensiunea datelor de test
- Afișează statistici de performanță

## Exemplu de Utilizare
```java
// Generare cheie nouă
SecretKey key = generateKey();

// Criptare text
String mesajOriginal = "Text secret";
byte[] iv = generateIV();
String mesajCriptat = encrypt(mesajOriginal, key, iv);

// Decriptare text
String mesajDecriptat = decrypt(mesajCriptat, key);

// Salvare cheie pentru utilizare ulterioară
saveKey(key, "cheie_secreta.bin");
```

## Note de Securitate
1. Folosește AES-GCM pentru autentificare și confidențialitate
2. IV unic pentru fiecare operație de criptare
3. Generare criptografic sigură pentru chei și IV-uri
4. Tag de autentificare de 128 biți
5. Mod debug activat pentru depanare (dezactivați în producție) 
