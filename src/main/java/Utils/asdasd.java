package Utils;


        import javax.crypto.*;
        import java.io.*;
        import java.util.Base64;
        import java.util.Scanner;

public class asdasd {
    private static Cipher cipher = null;
    private static Scanner scanner = new Scanner(System.in);

    public static void main(String[] args) throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("DESede");
        keyGenerator.init(168);

        SecretKey secretKey = keyGenerator.generateKey();
        cipher = Cipher.getInstance("DESede");

        String textToEncrypt = scanner.nextLine();
        System.out.println("Plain Text Before Encryption: " + textToEncrypt);

        byte[] plainTextByte = textToEncrypt.getBytes("UTF8");
        byte[] encryptedBytes = encrypt(plainTextByte, secretKey);

        String encryptedText = new String(encryptedBytes, "UTF8");
        System.out.println("Encrypted Text After Encryption: " + encryptedText);

        writeFile(encryptedBytes);

        byte[] encryptedTextFromFile = readFile();


        String decryptedText = new String(decrypt(encryptedTextFromFile, secretKey), "UTF8");
        System.out.println("Decrypted Text After Decryption: " + decryptedText);

    }

    static byte[] encrypt(byte[] plainTextByte, SecretKey secretKey)
            throws Exception {
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encryptedBytes = cipher.doFinal(plainTextByte);
        return encryptedBytes;
    }

    private static void writeFile(byte[] encryptedText) {
        File outputFile = new File("fichero.cifrado");

        try (FileOutputStream outputStream = new FileOutputStream(outputFile); ) {

            outputStream.write(encryptedText);  //write the bytes and your done.

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static byte[] decrypt(byte[] encryptedBytes, SecretKey secretKey)
            throws Exception {
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        cipher.update(encryptedBytes);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedBytes));
        return decryptedBytes;
    }

    private static byte[] readFile() {
        FileInputStream fin = null;
        File file = new File("fichero.cifrado");

        try {
            // create FileInputStream object
            fin = new FileInputStream(file);

            byte fileContent[] = new byte[(int)file.length()];

            // Reads up to certain bytes of data from this input stream into an array of bytes.
            fin.read(fileContent);
            //create string from byte array
            String s = new String(fileContent);
            System.out.println("File content: " + s);
            return fileContent;
        }
        catch (FileNotFoundException e) {
            System.out.println("File not found" + e);
        }
        catch (IOException ioe) {
            System.out.println("Exception while reading file " + ioe);
        }
        finally {
            // close the streams using close method
            try {
                if (fin != null) {
                    fin.close();
                }
            }
            catch (IOException ioe) {
                System.out.println("Error while closing stream: " + ioe);
            }
        }
        return null;
    }
}

