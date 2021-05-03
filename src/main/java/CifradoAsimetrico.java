import Utils.*;

import java.util.Scanner;

public class CifradoAsimetrico {


    public static void main(String[] args) {

        Scanner sc = new Scanner(System.in);
        byte[] message;
        Utils utils = new Utils();
        utils.keyPairGenerator();
        System.out.println("A continuación escriba el mensaje a cifrar.");
        message = sc.next().getBytes();
        utils.encryptAndDecryptFileWithPublicKey(message);
    }


}
