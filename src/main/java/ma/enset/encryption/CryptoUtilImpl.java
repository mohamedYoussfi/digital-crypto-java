package ma.enset.encryption;

import com.sun.deploy.security.CertType;
import javafx.scene.paint.CycleMethod;
import org.apache.commons.codec.binary.Hex;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Formatter;

public class CryptoUtilImpl {
    public String encodeToBase64(byte[] data){
        return Base64.getEncoder().encodeToString(data);
    }
    public byte[] decodeFromBase64(String dataBase64){
        return Base64.getDecoder().decode(dataBase64.getBytes());
    }
    public String encodeToBase64URL(byte[] data){
        return Base64.getUrlEncoder().encodeToString(data);
    }
    public byte[] decodeFromBase64URL(String dataBase64){
        return Base64.getUrlDecoder().decode(dataBase64.getBytes());
    }

    public String encodeToHex(byte[] data){
        return DatatypeConverter.printHexBinary(data);
    }
    public String encodeToHexApacheCodec(byte[] data){
        return Hex.encodeHexString(data);
    }
    public String encodeToHexNative(byte[] data){
        Formatter formatter=new Formatter();
        for(byte b:data){
            formatter.format("%02x",b);
        }
        return formatter.toString();
    }

    public SecretKey generateSecretKey()throws Exception{
        KeyGenerator keyGenerator=KeyGenerator.getInstance("AES");
        keyGenerator.init(256);
        return keyGenerator.generateKey();
    }

    public SecretKey generateSecretKey(String secret)throws Exception{
        SecretKey secretKey=new SecretKeySpec(secret.getBytes(),0,secret.length(),"AES");
        return secretKey;
    }

    public String encryptAES(byte[] data, SecretKey secretKey) throws Exception {
        Cipher cipher=Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE,secretKey);
        byte[] encryptedData = cipher.doFinal(data);
        String encodedEncryptedData = Base64.getEncoder().encodeToString(encryptedData);
        return encodedEncryptedData;
    }

    public byte[] decryptAES(String encodedEncryptedData, SecretKey secretKey) throws Exception {
        byte[] decodeEcryptedData = Base64.getDecoder().decode(encodedEncryptedData);
        Cipher cipher=Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE,secretKey);
        byte[] decryptedBytes = cipher.doFinal(decodeEcryptedData);
        return decryptedBytes;
    }

    public KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator=KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(512);
        return keyPairGenerator.generateKeyPair();
    }

    public PublicKey publicKeyFromBase64(String pkBase64) throws Exception {
        KeyFactory keyFactory=KeyFactory.getInstance("RSA");
        byte[] decodedPK = Base64.getDecoder().decode(pkBase64);
        PublicKey publicKey=keyFactory.generatePublic(new X509EncodedKeySpec(decodedPK));
        return publicKey;
    }

    public PrivateKey privateKeyFromBase64(String pkBase64) throws Exception {
        KeyFactory keyFactory=KeyFactory.getInstance("RSA");
        byte[] decodedPK = Base64.getDecoder().decode(pkBase64);
        PrivateKey privateKey=keyFactory.generatePrivate(new PKCS8EncodedKeySpec(decodedPK));
        return privateKey;
    }

    public String encryptRSA(byte[] data, PublicKey publicKey) throws Exception {
        Cipher cipher=Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE,publicKey);
        byte[] bytes = cipher.doFinal(data);
        return encodeToBase64(bytes);
    }

    public byte[] decryptRSA(String dataBase64, PrivateKey privateKey) throws Exception {
        Cipher cipher=Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE,privateKey);
        byte[] decodedEncryptedData = decodeFromBase64(dataBase64);
        byte[] decryptedData = cipher.doFinal(decodedEncryptedData);
        return decryptedData;
    }

    public PublicKey publicKeyFromCertificate(String fileName) throws Exception {
        FileInputStream fileInputStream=new FileInputStream(fileName);
        CertificateFactory certificateFactory=CertificateFactory.getInstance("X.509");
        Certificate certificate = certificateFactory.generateCertificate(fileInputStream);
        //System.out.println("=================================");
        //System.out.println(certificate.toString());
        //System.out.println("=================================");
        return certificate.getPublicKey();
    }
    public PrivateKey privateKeyFromJKS(String fileName, String jksPassWord, String alias) throws Exception {
        FileInputStream fileInputStream=new FileInputStream(fileName);
        KeyStore keyStore=KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(fileInputStream,jksPassWord.toCharArray());
        Key key = keyStore.getKey(alias, jksPassWord.toCharArray());
        PrivateKey privateKey= (PrivateKey) key;
        return privateKey;
    }

    public String hmacSign(byte[] data,String privateSecret) throws Exception {
        SecretKeySpec secretKeySpec=new SecretKeySpec(privateSecret.getBytes(),"HmacSHA256");
        Mac mac=Mac.getInstance("HmacSHA256");
        mac.init(secretKeySpec);
        byte[] signature = mac.doFinal(data);
        return Base64.getEncoder().encodeToString(signature);
    }
    public boolean hmacVerify(String signedDocument,String secret) throws Exception {
        SecretKeySpec secretKeySpec=new SecretKeySpec(secret.getBytes(),"HmacSHA256");
        Mac mac=Mac.getInstance("HmacSHA256");
        String[] splitedDocument=signedDocument.split("_.._");
        String document=splitedDocument[0];
        String documentSignature=splitedDocument[1];
        mac.init(secretKeySpec);
        byte[] sign = mac.doFinal(document.getBytes());
        String base64Sign=Base64.getEncoder().encodeToString(sign);
        return (base64Sign.equals(documentSignature));
    }

    public String rsaSign(byte[] data, PrivateKey privateKey) throws Exception {
        Signature signature=Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey,new SecureRandom());
        signature.update(data);
        byte[] sign = signature.sign();
        return Base64.getEncoder().encodeToString(sign);
    }

    public boolean rsaSignVerify(String signedDoc,PublicKey publicKey) throws Exception {
        Signature signature=Signature.getInstance("SHA256withRSA");
        signature.initVerify(publicKey);
        String[] data=signedDoc.split("_.._");
        String document=data[0];
        String sign=data[1];
        byte[] decodeSignature = Base64.getDecoder().decode(sign);
        signature.update(document.getBytes());
        boolean verify = signature.verify(decodeSignature);
        return verify;
    }



}
