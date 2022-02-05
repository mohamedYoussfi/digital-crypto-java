package ma.enset;

import ma.enset.encryption.CryptoUtilImpl;

public class Test1 {
    public static void main(String[] args) {
        CryptoUtilImpl cryptoUtil=new CryptoUtilImpl();
        String data="Hello from ENSET>>>";
        String dataBase64 = cryptoUtil.encodeToBase64(data.getBytes());
        String dataBase64Url = cryptoUtil.encodeToBase64URL(data.getBytes());
        System.out.println(dataBase64);
        System.out.println(dataBase64Url);

        byte[] decodedBytes = cryptoUtil.decodeFromBase64(dataBase64);
        System.out.println(new String(decodedBytes));
        byte[] decodedBytes2 = cryptoUtil.decodeFromBase64URL(dataBase64Url);
        System.out.println(new String(decodedBytes2));

        String s = cryptoUtil.encodeToHex(data.getBytes());
        String s1 = cryptoUtil.encodeToHexApacheCodec(data.getBytes());
        String s2 = cryptoUtil.encodeToHexNative(data.getBytes());
        System.out.println(s);
        System.out.println(s1);
        System.out.println(s2);

    }
}
