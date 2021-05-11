import Utils.*;
import java.util.Scanner;

/**
 * @author RNarvaiza
 *
 * On asymetric cipher we'll call a collection of functions to get a message, choose a public key, encrypt a message, write on file, and then, read and decrypt with a private key.
 * to finally print through console.
 */
public class CifradoAsimetrico {


    public static void main(String[] args) {

        Scanner sc = new Scanner(System.in);
        byte[] message;
        Utils utils = new Utils();
        utils.keyPairGenerator();
        System.out.println("A continuación escriba el mensaje a cifrar.");
        message = sc.nextLine().getBytes();
        utils.encryptAndDecryptFileWithPublicKey(message);
    }


}
