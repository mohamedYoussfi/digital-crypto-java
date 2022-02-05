package ma.enset;

import ma.enset.encryption.CryptoUtilImpl;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;

public class RSATest {
    public static void main(String[] args) throws Exception {
        CryptoUtilImpl cryptoUtil=new CryptoUtilImpl();
        KeyPair keyPair=cryptoUtil.generateKeyPair();
        PublicKey publicKey=keyPair.getPublic();
        String pkBase64=cryptoUtil.encodeToBase64(publicKey.getEncoded());
        System.out.println(pkBase64);
        PrivateKey privateKey=keyPair.getPrivate();
        String prvkBase64=cryptoUtil.encodeToBase64(privateKey.getEncoded());
        System.out.println(prvkBase64);
        System.out.println("==========================================");
        PublicKey publicKey1=cryptoUtil.publicKeyFromBase64(pkBase64);
        String data="Hello world ....";
        String encrypted = cryptoUtil.encryptRSA(data.getBytes(), publicKey1);
        System.out.println("Encrypted:");
        System.out.println(encrypted);

        PrivateKey privateKey1=cryptoUtil.privateKeyFromBase64(prvkBase64);
        System.out.println("Decrypted:");
        byte[] bytes = cryptoUtil.decryptRSA(encrypted, privateKey1);
        System.out.println(new String(bytes));
    }
}
