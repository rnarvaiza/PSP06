import Utils.Utils;

import javax.crypto.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Scanner;

public class CifradoSimetrico {

    public static File file = new File("src/main/resources/" + "fichero");

    private static Scanner sc = new Scanner(System.in);
    private static Cipher cipher = null;
    private static Utils utils= new Utils();
    static String printMessage = null;
    static byte[] plainChars = new byte[1024];
    static byte[] encryptedChars = new byte[1024];
    static KeyGenerator keyGen = null;
    public static void main(String[] args) {
        System.out.println("Introduzca texto a encriptar: ");
        System.out.println(encryptAndDecrypt(sc.nextLine()));;

    }

    public static String encryptAndDecrypt(String string){
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
            writeFileasd(plainChars);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException | IOException e) {
            System.out.println(e.getMessage());
        }
        return "Texto desencriptado: " + "\n\r" + printMessage;
    }

    public static boolean writeFileasd(byte[] buffer) throws IOException {


        boolean correcto = false;

        try
                (FileOutputStream fos = new FileOutputStream(file);)
        {
            fos.write(buffer);
            correcto = true;
        } catch (FileNotFoundException e) {
            System.out.println(e.getMessage());
        }
        return correcto;
    }

}
