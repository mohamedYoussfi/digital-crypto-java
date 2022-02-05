package ma.enset;

import javax.crypto.Cipher;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class TestRSADecrypt {
    public static void main(String[] args) throws Exception {

   /*
   Private key:
MIIBVgIBADANBgkqhkiG9w0BAQEFAASCAUAwggE8AgEAAkEAlVcVBPM4+bap9J8MZgqdXsUvV+O31zsSTajGoYOQmqCeBtZ8008LfrOf+pUwypi7mZUFdIBYqjqPk4THwoZUKwIDAQABAkABni3mHdRyMB5rPgXeXSMTUcOPijIFrOgn2zo7qbc5VZvgDhHdWj4gbbmHXrek+Lq1rOxYdFzQUsC+4gJYcuiRAiEA1SlD+r99ubE/IInIfOvbhHUr8LJr6jwkeb1XvBeG3N8CIQCzWljY0igK490TmRgOH4F6D6FSRzui0zNEHrzT+d6mNQIhAItB1T54YauxpxsbyJYMBDJp1hX+ik/RkMbTswCXoiyjAiEAjA9S8Md1Q8PcQlC861KJPzPzjBhapvX9xAWo+nTX/b0CIQDIkp2XW+fQZW1Edn5yx43u9IWIqzDX8TOMjGUgbXfS6Q==
Public Key
MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAJVXFQTzOPm2qfSfDGYKnV7FL1fjt9c7Ek2oxqGDkJqgngbWfNNPC36zn/qVMMqYu5mVBXSAWKo6j5OEx8KGVCsCAwEAAQ==
    */
   String privateKeyBase64="MIIBVgIBADANBgkqhkiG9w0BAQEFAASCAUAwggE8AgEAAkEAlVcVBPM4+bap9J8MZgqdXsUvV+O31zsSTajGoYOQmqCeBtZ8008LfrOf+pUwypi7mZUFdIBYqjqPk4THwoZUKwIDAQABAkABni3mHdRyMB5rPgXeXSMTUcOPijIFrOgn2zo7qbc5VZvgDhHdWj4gbbmHXrek+Lq1rOxYdFzQUsC+4gJYcuiRAiEA1SlD+r99ubE/IInIfOvbhHUr8LJr6jwkeb1XvBeG3N8CIQCzWljY0igK490TmRgOH4F6D6FSRzui0zNEHrzT+d6mNQIhAItB1T54YauxpxsbyJYMBDJp1hX+ik/RkMbTswCXoiyjAiEAjA9S8Md1Q8PcQlC861KJPzPzjBhapvX9xAWo+nTX/b0CIQDIkp2XW+fQZW1Edn5yx43u9IWIqzDX8TOMjGUgbXfS6Q==";
   KeyFactory keyFactory=KeyFactory.getInstance("RSA");
        byte[] decodeKey = Base64.getDecoder().decode(privateKeyBase64);
        PrivateKey privateKey=keyFactory.generatePrivate(new PKCS8EncodedKeySpec(decodeKey));
        String encryptedData="gwEnA0onjSMJib6RjGIpKZ+YL5Y68qEwnXhoXtz0qW5WXjWeKvSHcNF0czPWzENrQwhDBGOCNWImkTXY9VPGMw==";
        System.out.println("Encrypted Data:");
        System.out.println(encryptedData);
        byte[] decodeEncryptedData = Base64.getDecoder().decode(encryptedData);
        Cipher cipher=Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE,privateKey);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedData));
        System.out.println("Decrypted message:");
        System.out.println(new String(decryptedBytes));

    }
}
