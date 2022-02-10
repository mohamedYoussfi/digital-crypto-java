package ma.enset;

import ma.enset.encryption.CryptoUtilImpl;

public class TestSignature {
    public static void main(String[] args) throws Exception {
        CryptoUtilImpl cryptoUtil=new CryptoUtilImpl();
        String secret="azerty";
        String document="This is my message";
        String signature = cryptoUtil.hmacSign(document.getBytes(), secret);
        String signedDocument=document+"_.._"+signature;
        System.out.println(signedDocument);
        System.out.println("===========================");
        String signedDoc="This is my message_.._oWfD3YCesNpVWhygSPBzF+N9X8NJpa2wyxBe6MZB6V8=";
        String sec="azerty";
        System.out.println("Signature verification");
        boolean signatureVerifResult = cryptoUtil.hmacVerify(signedDoc, secret);
        System.out.println(signatureVerifResult==true?"Signature OK":"Signature Not OK");

    }
}
