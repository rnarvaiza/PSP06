import Utils.Utils;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Scanner;

public class CifradoSimetrico {

    public static File file = new File("src/main/resources/" + "fichero");
    //public static File key_file = new File ("src/main/resources/" + "clave");

    private static Scanner sc = new Scanner(System.in);

    public static void main(String[] args) {

        String option, message = null;
        EncryptMethods encryptMethods = new EncryptMethods();

        System.out.println("Please input text to encrypt: ");
        message = sc.nextLine();
        System.out.println("Choose between following encrypt methods: \n#1 AES \n#2 DESede \n XXX");
        option = sc.nextLine();
        encryptMethods.encrypt(message, Integer.valueOf(option));
        System.out.println("Choose between following decrypt methods: \n#1 AES \n#2 DESede \n XXX");
        option = sc.nextLine();
        encryptMethods.decrypt(Integer.valueOf(option));




    }

    public static class EncryptMethods{

        static Cipher cipher = null;
        static Utils utils= new Utils();
        static String printMessage = null;
        static String inputText = null;
        static String encryptAlgorithm = null;
        static byte[] plainChars = new byte[1024];
        static byte[] encryptedChars = new byte[1024];

        private SecretKey secretKey = null;

        public void encrypt(String string, int option) {
            switch (option) {
                case 1:
                    try {
                        generateKey("AES", 128);
                        plainChars = string.getBytes("UTF8");
                        cipherInstance(plainChars, "AES/ECB/PKCS5Padding", loadPublicKey("src/main/resources/" + "clave", "AES"), Cipher.ENCRYPT_MODE);
                    } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException | IOException | InvalidKeySpecException e ) {
                        System.out.println(e.getMessage());
                    }
                    break;
                case 2:
                    try {
                        generateKey("DESede", 168);
                        plainChars = string.getBytes("UTF8");
                        cipherInstance(plainChars, "DESede", loadPublicKey("src/main/resources/" + "clave", "DESede"), Cipher.ENCRYPT_MODE);
                    } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException | IOException | InvalidKeySpecException e ) {
                        System.out.println(e.getMessage());
                    }

                    break;
                case 3:

                    break;

                default:
            }
        }

        public String cipherInstance(byte[] chars, String algorithm, Key key, int cipherMode) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException {
            String returnedFromCipher = null;
            Cipher cipher = Cipher.getInstance(algorithm);
            cipher.init(cipherMode, key);
            if(cipherMode == Cipher.ENCRYPT_MODE){
                byte[] encrypted = cipher.doFinal(chars);
                writeFile(encrypted, file);
            }
            if (cipherMode == Cipher.DECRYPT_MODE){
                returnedFromCipher = new String(cipher.doFinal(utils.readFile(file)));
            }
            return returnedFromCipher;
        }

        public void generateKey(String encryptAlgorithm, int keySize) throws NoSuchAlgorithmException, IOException {
            KeyGenerator keyGen = KeyGenerator.getInstance(encryptAlgorithm);
            keyGen.init(keySize);
            Key key = keyGen.generateKey();
            saveKey(key, "src/main/resources/" + "clave");

        }

        public void decrypt(int option) {
            switch (option) {
                case 1:
                    try {
                        System.out.println("This is the decrypted message: "+ cipherInstance(plainChars, "AES/ECB/PKCS5Padding", loadPublicKey("src/main/resources/" + "clave", "AES"), Cipher.DECRYPT_MODE));
                    } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException | IOException | InvalidKeySpecException e ) {
                        System.out.println(e.getMessage());
                    }
                    break;
                case 2:
                    try {
                        System.out.println("This is the decrypted message: "+ cipherInstance(plainChars, "DESede", loadPublicKey("src/main/resources/" + "clave", "DESede"), Cipher.DECRYPT_MODE));
                    } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException | IOException | InvalidKeySpecException e ) {
                        System.out.println(e.getMessage());
                    }
                    break;
                case 3:

                    break;

                default:
            }
        }

        public static byte[] charsetToEncrypt(SecretKey secretKey, byte[] bytes, String encryptAlgorithm) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
            cipher = Cipher.getInstance(encryptAlgorithm);
            cipher.init((Cipher.ENCRYPT_MODE), secretKey);
           return cipher.doFinal(bytes);
        }

        public static byte[] charsetToDecrypt(SecretKey secretKey, String encryptAlgorithm) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

            cipher = Cipher.getInstance(encryptAlgorithm);
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            encryptedChars = utils.readFile(file);
            cipher.update(encryptedChars);
            return cipher.doFinal(encryptedChars);

        }

        public SecretKey getSecretKey() {
            return secretKey;
        }

        public void setSecretKey(SecretKey secretKey) {
            this.secretKey = secretKey;
        }
    }

/*
        try {
            plainChars = string.getBytes("UTF8");
            keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(256);
            SecretKey key = keyGen.generateKey();
            cipher = cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            encryptedChars = cipher.doFinal(plainChars);
            Utils.writeFile(encryptedChars);
            System.out.println("Texto encriptado: " + new String(encryptedChars));
            cipher.init(Cipher.DECRYPT_MODE, key);
            encryptedChars = utils.readFile();
            cipher.update(encryptedChars);
            plainChars = cipher.doFinal(encryptedChars);
            printMessage = new String(plainChars, "UTF8");
            writeFile(plainChars);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException | IOException e) {
            System.out.println(e.getMessage());
        }
        return "Texto desencriptado: " + "\n\r" + printMessage;
    }

 */

    public static boolean writeFile(byte[] buffer, File fileName) throws IOException {

        System.out.println("Encrypted message to be saved on file: " + new String(buffer, "UTF8"));//TODO es necesario siempre especificar el charset?
        boolean correcto = false;

        try
                (FileOutputStream fos = new FileOutputStream(fileName);)
        {
            fos.write(buffer);
            correcto = true;
        } catch (FileNotFoundException e) {
            System.out.println(e.getMessage());
        }
        return correcto;
    }

    public static void saveKey(Key key, String fileName) throws IOException {
        byte[] publicKeyBytes = key.getEncoded();
        FileOutputStream fos = new FileOutputStream(fileName);
        fos.write(publicKeyBytes);
        fos.close();
    }

    private static SecretKeySpec loadPublicKey(String fileName, String encryptionMethod) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        FileInputStream fis = new FileInputStream(fileName);
        int numBtyes = fis.available();
        byte[] bytes = new byte[numBtyes];
        fis.read(bytes);
        fis.close();
        SecretKeySpec secretKeySpec = new SecretKeySpec(bytes, encryptionMethod);
        return secretKeySpec;
    }

}
