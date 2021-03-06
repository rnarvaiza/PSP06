package Utils;

import javax.crypto.*;
import java.io.*;
import java.security.*;

/**
 * @author RNarvaiza
 *
 * Sandbox for implements encrypt&decrypt texts with public&private keys
 */

public class Utils {

    public static final String RESOURCES_PATH = "src/main/resources/";
    private static PublicKey pubKey = null;
    private static PrivateKey privKey = null;
    public static File file = new File(RESOURCES_PATH + "fichero.cifrado");


    /**
     * Function designed to generate an instance of KeyPair with a given algorithm.
     */
    public void keyPairGenerator(){
        KeyPairGenerator kpg = null;
        try {
            kpg = KeyPairGenerator.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();

        //Generate private & public keys.
        setPrivKey(kp.getPrivate());
        setPubKey(kp.getPublic());
    }

    /**
     * Function designed to collect a string , use a designed encryption method and encrypt.
     * After the encryption function will write on file and then call to a reader and decrypt with the given private key.
     * @param bufferNoSecure
     */

    public void encryptAndDecryptFileWithPublicKey(byte[] bufferNoSecure){
            boolean escribe = true;
            byte[] buffer;
        try {
            System.out.println("\nMensaje no seguro :");
            mostrarBytes(bufferNoSecure);
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, getPubKey());
            byte[] cipherBuffer = cipher.doFinal(bufferNoSecure);
            writeFile(cipherBuffer);
            System.out.println("\nSe ha cifrado el mensaje: ");
            mostrarBytes(cipherBuffer);
            cipher.init(Cipher.DECRYPT_MODE, getPrivKey());
            buffer = cipher.doFinal(readFile(file));
            System.out.println("\nSe ha descifrado el mensaje: ");
            mostrarBytes(buffer);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException | IOException e) {
            System.out.println(e.getMessage());
            escribe = false;
        }
        if(escribe){
            System.out.println("\n##Info de ejecuci??n del programa de encriptado##  Fichero cifrado, guardado, leido y descifrado con ??xito.");
        }
    }


    public static void mostrarBytes(byte[] buffer) throws IOException {//Printer
        System.out.write(buffer);
    }



    public static boolean writeFile(byte[] buffer) throws IOException {//FileWriter declared on try with resources


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

    public byte[] readFile(File file){//Reader declared on try with resources

        byte[] encryptedBuffer = new byte[(int) file.length()];

        try (FileInputStream fileInputStream = new FileInputStream(file);){
            fileInputStream.read(encryptedBuffer);
        } catch (FileNotFoundException e) {
            System.out.println(e.getMessage());
        } catch (IOException e) {
            System.out.println(e.getMessage());
        }

        return encryptedBuffer;
    }

    //Getters & Setters.

    public PublicKey getPubKey() {
        return pubKey;
    }

    public void setPubKey(PublicKey pubKey) {
        this.pubKey = pubKey;
    }

    public PrivateKey getPrivKey() {
        return privKey;
    }

    public void setPrivKey(PrivateKey privKey) {
        this.privKey = privKey;
    }
}
