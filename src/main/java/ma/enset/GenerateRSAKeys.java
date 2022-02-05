package ma.enset;

import ma.enset.encryption.CryptoUtilImpl;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

public class GenerateRSAKeys {
    public static void main(String[] args) throws Exception {
        CryptoUtilImpl cryptoUtil=new CryptoUtilImpl();
        KeyPair keyPair = cryptoUtil.generateKeyPair();
        PrivateKey privateKey=keyPair.getPrivate();
        PublicKey publicKey=keyPair.getPublic();
        System.out.println("Private key:");
        //System.out.println(privateKey.getEncoded().length);
        //System.out.println(Arrays.toString(privateKey.getEncoded()));
        System.out.println(Base64.getEncoder().encodeToString(privateKey.getEncoded()));
        System.out.println("Public Key");
        //System.out.println(Arrays.toString(publicKey.getEncoded()));
        //System.out.println(publicKey.getEncoded().length);
        System.out.println(Base64.getEncoder().encodeToString(publicKey.getEncoded()));
    }
}
