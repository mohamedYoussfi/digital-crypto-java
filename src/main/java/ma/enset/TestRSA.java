package ma.enset;

import ma.enset.encryption.CryptoUtilImpl;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

public class TestRSA {
    public static void main(String[] args) throws Exception {

   /*
   Private key:
MIIBVgIBADANBgkqhkiG9w0BAQEFAASCAUAwggE8AgEAAkEAlVcVBPM4+bap9J8MZgqdXsUvV+O31zsSTajGoYOQmqCeBtZ8008LfrOf+pUwypi7mZUFdIBYqjqPk4THwoZUKwIDAQABAkABni3mHdRyMB5rPgXeXSMTUcOPijIFrOgn2zo7qbc5VZvgDhHdWj4gbbmHXrek+Lq1rOxYdFzQUsC+4gJYcuiRAiEA1SlD+r99ubE/IInIfOvbhHUr8LJr6jwkeb1XvBeG3N8CIQCzWljY0igK490TmRgOH4F6D6FSRzui0zNEHrzT+d6mNQIhAItB1T54YauxpxsbyJYMBDJp1hX+ik/RkMbTswCXoiyjAiEAjA9S8Md1Q8PcQlC861KJPzPzjBhapvX9xAWo+nTX/b0CIQDIkp2XW+fQZW1Edn5yx43u9IWIqzDX8TOMjGUgbXfS6Q==
Public Key
MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAJVXFQTzOPm2qfSfDGYKnV7FL1fjt9c7Ek2oxqGDkJqgngbWfNNPC36zn/qVMMqYu5mVBXSAWKo6j5OEx8KGVCsCAwEAAQ==
    */
   String publicKeyBase64="MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAJVXFQTzOPm2qfSfDGYKnV7FL1fjt9c7Ek2oxqGDkJqgngbWfNNPC36zn/qVMMqYu5mVBXSAWKo6j5OEx8KGVCsCAwEAAQ==";
   KeyFactory keyFactory=KeyFactory.getInstance("RSA");
        byte[] decodeKey = Base64.getDecoder().decode(publicKeyBase64);
        PublicKey publicKey=keyFactory.generatePublic(new X509EncodedKeySpec(decodeKey));
        String data="Voici mon message clair à chiffrer";
        Cipher cipher=Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE,publicKey);
        byte[] encryptedBytes = cipher.doFinal(data.getBytes());
        System.out.println("Encrypted message:");
        System.out.println(Base64.getEncoder().encodeToString(encryptedBytes));

    }
}
