package ma.enset;

import ma.enset.encryption.CryptoUtilImpl;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

public class TestRsaSign {
    public static void main(String[] args) throws Exception {
        CryptoUtilImpl cryptoUtil=new CryptoUtilImpl();
        PrivateKey privateKey= cryptoUtil.privateKeyFromJKS("youssfi.jks","123456","youssfi");
        String data="This is my message {}=>";
        String signature = cryptoUtil.rsaSign(data.getBytes(), privateKey);
        String signedDoc=data+"_.._"+signature;
        System.out.println(signedDoc);
        System.out.println("===================================");
        System.out.println("Signature verification");
        String signedDocRecived="This is my message {}=>_.._kABXhdjsV0VpQKQdCoPpfZ73JEV6t3P909lgOqjBAMwwCYxPnV0fDyUN+gyezUAQb1KphCxoymowQgVpkcj7yL3uXl/CtWRu6MJfeQkul6M+3vAUzG5fkI7jUZfuuJM1ClH2tMlmL5D7+BWwvV9aSD/AVVNA0mU+J706f4FCaMr03FDFOV3yGeGUBBPOTsE7BlMJodMn2uH6Q65hblN8B10wGV9PoD06pdSrNbHmeltYJyNq1OS3Hq65to3U/P67aTn0FFHgeG/qRdmduKN8nWWcB6ve0ETOomVVsdps9eR4hbljqqw7TBRGCeajf7toaKG5CiMUYJjv3Cc4QprGCQ==";
        PublicKey publicKey=cryptoUtil.publicKeyFromCertificate("myCertificate.cert");
        boolean b = cryptoUtil.rsaSignVerify(signedDocRecived, publicKey);
        System.out.println(b?"Signature OK":"Signature Not OK");
    }
}
