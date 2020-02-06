import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPublicKeySpec;
import java.util.Arrays;
import java.util.Base64;


class Verify {

    public static void main(String[] args) throws Exception {
        String publicKeyBase64url = args[0];
        String signatureToVerifyBase64url = args[1];
        String text = args[2];

        System.out.println(
                "Public Key (Base64url): " + publicKeyBase64url);
        System.out.println(
                "Signature (Base64url): " + signatureToVerifyBase64url);
        System.out.println("Text: " + text);

        byte[] publicKey =
            Base64.getUrlDecoder().decode(publicKeyBase64url);
        byte[] signatureToVerify =
            Base64.getUrlDecoder().decode(signatureToVerifyBase64url);
        byte[] data = text.getBytes(StandardCharsets.UTF_8);

        byte[] x = Arrays.copyOfRange(publicKey, 27, 59);
        byte[] y = Arrays.copyOfRange(publicKey, 59, 91);

        ECPoint ecPoint = new ECPoint(new BigInteger(x), new BigInteger(y));

        AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
        parameters.init(new ECGenParameterSpec("secp256r1"));
        ECParameterSpec parameterSpec =
            parameters.getParameterSpec(ECParameterSpec.class);

        ECPublicKeySpec keySpec = new ECPublicKeySpec(ecPoint, parameterSpec);

        KeyFactory keyFactory = KeyFactory.getInstance("EC");

        Signature signature = Signature.getInstance("SHA256withECDSA");
        signature.initVerify(keyFactory.generatePublic(keySpec));
        signature.update(data);

        boolean isValid = signature.verify(signatureToVerify);
        System.out.println("Is valid: " + isValid);
    }
}

