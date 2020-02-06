import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPublicKeySpec;
import java.util.Arrays;
import java.util.Base64;


class Sign {

    public static void main(String[] args) throws Exception {
        String text = "test";

        byte[] data = text.getBytes(StandardCharsets.UTF_8);

        ECGenParameterSpec genParameterSpec =
            new ECGenParameterSpec("secp256r1");
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(genParameterSpec, new SecureRandom());

        KeyPair keyPair = generator.generateKeyPair();

        Signature signature = Signature.getInstance("SHA256withECDSA");
        signature.initSign(keyPair.getPrivate());
        signature.update(data);

        byte[] signatureToVerify = signature.sign();
        String result = new String(
                Base64.getUrlEncoder().encode(signatureToVerify));

        System.out.println("Signature: " + result);

        byte[] x = Arrays.copyOfRange(
                keyPair.getPublic().getEncoded(), 27, 59);
        byte[] y = Arrays.copyOfRange(
                keyPair.getPublic().getEncoded(), 59, 91);

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(0x04);
        outputStream.write(x);
        outputStream.write(y);

        byte[] publicKey = outputStream.toByteArray();
        String publicKeyString = new String(
                Base64.getUrlEncoder().encode(publicKey));

        System.out.println("Public key: " + publicKeyString);

        ECPoint ecPoint = new ECPoint(new BigInteger(x), new BigInteger(y));

        AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
        parameters.init(new ECGenParameterSpec("secp256r1"));
        ECParameterSpec parameterSpec =
            parameters.getParameterSpec(ECParameterSpec.class);

        ECPublicKeySpec keySpec = new ECPublicKeySpec(ecPoint, parameterSpec);

        KeyFactory keyFactory = KeyFactory.getInstance("EC");

        signature = Signature.getInstance("SHA256withECDSA");
        signature.initVerify(keyFactory.generatePublic(keySpec));
        signature.update(data);

        boolean isValid = signature.verify(signatureToVerify);
        System.out.println("Is valid: " + isValid);
    }
}

