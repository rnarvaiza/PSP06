import Utils.Utils;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Scanner;

/**
 * @author RNarvaiza
 *
 * CifradoSimetrico class is container class designed to show the decryption menu.
 */

public class CifradoSimetrico {

    public static File file = new File("src/main/resources/" + "fichero");

    private static Scanner sc = new Scanner(System.in);

    public static void main(String[] args) {

        String option = " ", message = null;
        EncryptMethods encryptMethods = new EncryptMethods();

        System.out.println("Please input text to encrypt: ");
        message = sc.nextLine();
        while(!option.equalsIgnoreCase("1") && !option.equalsIgnoreCase("2") && !option.equalsIgnoreCase("3")){
            System.out.println("Choose between following encrypt methods: \n#1 AES \n#2 DESede \n#3 Blowfish");
            option = sc.nextLine();
        }
        encryptMethods.encrypt(message, Integer.valueOf(option));
        option = "0";
        while(!option.equalsIgnoreCase("1") && !option.equalsIgnoreCase("2") && !option.equalsIgnoreCase("3")){
            System.out.println("Choose between following decrypt methods: \n#1 AES \n#2 DESede \n#3 Blowfish");
            option = sc.nextLine();
        }

        encryptMethods.decrypt(Integer.valueOf(option));

    }

    /**
     * EncryptMethods is a static class designed to give support to the menu.
     * Here we'll get instantiated two different functions. Encrypt and decrypt.
     */
    public static class EncryptMethods{
        static Utils utils= new Utils();
        static byte[] plainChars = new byte[1024];


        private SecretKey secretKey = null;


        /**
         * Encrypt option is designed to take input from menu.
         * According to this inputs, we'll instantiate cipher with a given parameters.
         * @param string
         * @param option
         */
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
                    try{
                        generateKey("Blowfish", 128);
                        plainChars = string.getBytes("UTF8");
                        cipherInstance(plainChars, "Blowfish", loadPublicKey("src/main/resources/" + "clave", "Blowfish"), Cipher.ENCRYPT_MODE);
                    }catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException | IOException | InvalidKeySpecException e ) {
                    System.out.println(e.getMessage());
                }
                    break;
            }
        }

        /**
         * CipherInstance is the main method on the hierarchy of this class.
         * We'll instantiate inside cipher and we'll give through parameters all the needed info.
         * Inside this we will filter de cipherMode to choose the main two actions that we'll need, encrypt or decrypt.
         * @param chars will provide an array of bytes to be encrypted.
         * @param algorithm is the requested cipher method.
         * @param key is the generated and saved key to be used on encryption and decryption.
         * @param cipherMode will choose the cipher mode between encrypt or decrypt.
         * @return
         * @throws NoSuchPaddingException
         * @throws NoSuchAlgorithmException
         * @throws InvalidKeyException
         * @throws IllegalBlockSizeException
         * @throws BadPaddingException
         * @throws IOException
         */

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

        /**
         * Here we generate a key with a given algorithm and store on a file to be retrieved later.
         * This key will be called on encryption and decryption to be used with cipher.
         * @param encryptAlgorithm
         * @param keySize
         * @throws NoSuchAlgorithmException
         * @throws IOException
         */

        public void generateKey(String encryptAlgorithm, int keySize) throws NoSuchAlgorithmException, IOException {
            KeyGenerator keyGen = KeyGenerator.getInstance(encryptAlgorithm);
            keyGen.init(keySize);
            Key key = keyGen.generateKey();
            saveKey(key, "src/main/resources/" + "clave");

        }

        /**
         * Parallel as encrypt, this function will call a bunch of methods according to the menu inputs to decrypt a file.
         * @param option
         */

        public void decrypt(int option) {
            switch (option) {
                case 1:
                    try {
                        System.out.println("This is the decrypted message: ' "+ cipherInstance(plainChars, "AES/ECB/PKCS5Padding", loadPublicKey("src/main/resources/" + "clave", "AES"), Cipher.DECRYPT_MODE) + " '");
                    } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException | IOException | InvalidKeySpecException e ) {
                        System.out.println(e.getMessage());
                    }
                    break;
                case 2:
                    try {
                        System.out.println("This is the decrypted message: ' "+ cipherInstance(plainChars, "DESede", loadPublicKey("src/main/resources/" + "clave", "DESede"), Cipher.DECRYPT_MODE) + " '");
                    } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException | IOException | InvalidKeySpecException e ) {
                        System.out.println(e.getMessage());
                    }
                    break;
                case 3:
                    try {
                        System.out.println("This is the decrypted message: ' "+ cipherInstance(plainChars, "Blowfish", loadPublicKey("src/main/resources/" + "clave", "Blowfish"), Cipher.DECRYPT_MODE) + " '");
                    } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException | IOException | InvalidKeySpecException e ) {
                        System.out.println(e.getMessage());
                    }
                    break;

            }
        }

    }

    public static boolean writeFile(byte[] buffer, File fileName) throws IOException {//Standar writer which writes an array of bytes on a file.

        System.out.println("Encrypted message to be saved on file: ' " + new String(buffer, "UTF8") + " '");
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

    public static void saveKey(Key key, String fileName) throws IOException {//Writer designed to store the generated key in keyGen.
        byte[] publicKeyBytes = key.getEncoded();
        FileOutputStream fos = new FileOutputStream(fileName);
        fos.write(publicKeyBytes);
        fos.close();
    }

    /**
     * Function that will read a file and generate a SecretKeySpec to be used on encrypt and decrypt menu.
     * @param fileName
     * @param encryptionMethod
     * @return
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
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
