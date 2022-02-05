package ma.enset;

import ma.enset.encryption.CryptoUtilImpl;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;

public class SymetricCrypto {
    public static void main(String[] args) throws Exception {
        CryptoUtilImpl cryptoUtil=new CryptoUtilImpl();
        SecretKey secretKey=cryptoUtil.generateSecretKey();
        SecretKey secretKey2=cryptoUtil.generateSecretKey("azerty_azerty_az");
        byte[] secretKeyBytes = secretKey.getEncoded();
        System.out.println(Arrays.toString(secretKeyBytes));
        String encodedSecretKey = Base64.getEncoder().encodeToString(secretKeyBytes);
        System.out.println(encodedSecretKey);
        System.out.println("=====================================");
        String data="My Data .....";
        String encryptedData = cryptoUtil.encryptAES(data.getBytes(), secretKey2);
        System.out.println(encryptedData); //GsItoZZCEZql4taikMjlSw==
        byte[] decryptedBytes = cryptoUtil.decryptAES(encryptedData, secretKey2);
        System.out.println(new String(decryptedBytes));
    }
}
