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
        String publicKeyBase64url =
            "BO1FJT1Osp9w9Rslm8otzcKRdJ80Og3rGly2gDk0grXDlRTSRLdy7feEMenq3JFn6oEhUzztG6ZVHMtJCLAl5jI=";
        String text = "test";
        String signatureToVerifyBase64url = args[0];

        System.out.println(
                "Public Key (Base64url): " + publicKeyBase64url);
        System.out.println("Text: " + text);
        System.out.println(
                "Signature (Base64url): " + signatureToVerifyBase64url);

        byte[] publicKey =
            Base64.getUrlDecoder().decode(publicKeyBase64url);
        byte[] signatureToVerify =
            Base64.getUrlDecoder().decode(signatureToVerifyBase64url);
        byte[] data = text.getBytes(StandardCharsets.UTF_8);

        byte[] x = Arrays.copyOfRange(publicKey, 1, 33);
        byte[] y = Arrays.copyOfRange(publicKey, 33, 65);

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

