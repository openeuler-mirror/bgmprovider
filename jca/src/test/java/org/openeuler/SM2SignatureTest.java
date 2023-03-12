package org.openeuler;

import java.math.BigInteger;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.jcajce.spec.SM2ParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECConstants;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.test.SimpleTest;
import org.bouncycastle.util.test.TestRandomBigInteger;
import org.junit.BeforeClass;
import org.junit.Test;
import org.openeuler.util.ECNamedCurve;

import static org.junit.Assert.assertTrue;

public class SM2SignatureTest
{
    public String getName()
    {
        return "SM2";
    }

    private void doSignerTestFp()
            throws Exception
    {

        Security.insertProviderAt(new BGMJCEProvider(), 1);
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("SM2");

        KeyPair kp = kpGen.generateKeyPair();

        Signature signer = Signature.getInstance("SM3withSM2");

        byte[] pub = kp.getPublic().getEncoded();
        byte[] pri = kp.getPrivate().getEncoded();


        // repetition test
        final int times = 15;
        String random = "";
        for (int i = 0; i < times; i++)
        {
            random += "6CB28D99385C175C94F94E934817663FC176D925DD72B727260DBAAE1FB2F96F";
        }
        signer.initSign(kp.getPrivate());

        byte[] msg = Strings.toByteArray("message digest");

        Signature verifier = Signature.getInstance("SM3withSM2");

        verifier.initVerify(kp.getPublic());

        for (int i = 0; i < times; i++)
        {
            signer.update(msg, 0, msg.length);

            byte[] sig = signer.sign();

            BigInteger[] rs = decode(sig);

            if (!rs[0].equals(new BigInteger("142003045145307949648390139601348804584263815948774878435105933234718693866223", 16))) {
                System.out.println("r wrong");
            };
            if (!rs[1].equals(new BigInteger("55568916988209236694564442401567533134457592197908164162227337533317268484685", 16))) {
                System.out.println("s wrong");
            };

            verifier.update(msg, 0, msg.length);

            if (!verifier.verify(sig)) {
                System.out.println("verification failed i=" + i);
            }
        }
    }


    private static BigInteger[] decode(byte[] sig)
    {
        ASN1Sequence s = ASN1Sequence.getInstance(sig);

        return new BigInteger[] { ASN1Integer.getInstance(s.getObjectAt(0)).getValue(),
                ASN1Integer.getInstance(s.getObjectAt(1)).getValue() };
    }


    public static void main(
            String[]    args) throws Exception {

        SM2SignatureTest sm2SignatureTest = new SM2SignatureTest();
        sm2SignatureTest.doSignerTestFp();
    }

    private static final byte[] INFO = "message digest".getBytes();

    private static final byte[] PUBLIC_KEY_BYTES = new byte[]{
            48, 89, 48, 19, 6, 7, 42, -122, 72, -50, 61, 2, 1, 6, 8, 42, -127, 28, -49, 85, 1, -126, 45, 3, 66, 0, 4, 22, -10, 83, 120, 20, 2, -23, -82, 8, -5, 107, 65, -79, -22, 8, -101, -115, -58, -108, 53, 5, -9, -11, 7, -100, -85, 31, 82, 30, -70, 118, 82, -25, 106, 57, 14, 67, -94, 123, -56, 80, -78, -80, 28, -1, -123, -105, -85, -70, 81, -29, -105, 87, -113, -75, 17, 50, 87, -49, -31, -33, -29, -13, -80
    };
    private static final byte[] PRIVATE_KEY_BYTES = new byte[]{
            48, -127, -109, 2, 1, 0, 48, 19, 6, 7, 42, -122, 72, -50, 61, 2, 1, 6, 8, 42, -127, 28, -49, 85, 1, -126, 45, 4, 121, 48, 119, 2, 1, 1, 4, 32, 69, -84, 64, -106, -86, -61, 89, -21, 63, 115, 75, 34, 68, 40, -126, 90, 88, -7, -28, 38, 33, -117, 91, -5, 42, -74, -27, 90, -9, 116, -122, -35, -96, 10, 6, 8, 42, -127, 28, -49, 85, 1, -126, 45, -95, 68, 3, 66, 0, 4, 22, -10, 83, 120, 20, 2, -23, -82, 8, -5, 107, 65, -79, -22, 8, -101, -115, -58, -108, 53, 5, -9, -11, 7, -100, -85, 31, 82, 30, -70, 118, 82, -25, 106, 57, 14, 67, -94, 123, -56, 80, -78, -80, 28, -1, -123, -105, -85, -70, 81, -29, -105, 87, -113, -75, 17, 50, 87, -49, -31, -33, -29, -13, -80
    };

    // 48, 68, 2, 32, 127, -110, 114, 105, -106, -117, 119, -76, -1, -109, 3, 63, -18, -116, 42, 3, -97, 33, 84, 109, 110, -118, 101, 15, 48, -74, -106, 113, -47, -73, -57, -36, 2, 32, 121, 49, 94, 20, -65, 25, 26, 115, 40, 43, -3, -115, 68, -30, -115, -115, -70, 90, -88, -6, 19, -88, 122, -61, -73, -9, 2, 13, 76, -125, 62, -20
    private static final byte[] SIGN_BYTES = new byte[]{
            48, 69, 2, 33, 0, -119, 72, -73, 29, -1, 37, 102, 38, -91, -125, -118, -75, -90, -110, 30, -110, 125, 113, -79, -106, -21, -33, 35, 97, -118, 83, 113, 67, -70, -18, -88, 115, 2, 32, 7, -73, -35, 125, 73, -15, 127, -56, -68, 116, -27, 124, -116, -120, -25, -63, 74, -58, 93, 62, 84, 59, -66, 26, 65, 74, 83, 8, -18, 114, -38, 119
    };

    private static PrivateKey privateKey;

    private static PublicKey publicKey;

    /**
     * Init private key and public key
     */
    @BeforeClass
    public static void beforeClass() throws Exception {
        Security.insertProviderAt(new BGMJCEProvider(), 1);
        KeyFactory keyFactory = KeyFactory.getInstance("SM2");
        publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(PUBLIC_KEY_BYTES));
        privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(PRIVATE_KEY_BYTES));
    }

    /**
     * Test sign and verify
     */
    @Test
    public void testVerify() throws Exception {
        boolean verify = verify(SIGN_BYTES);
        assertTrue(verify);
    }

    @Test
    public void testSignAndVerify() throws Exception {
        byte[] signBytes = sign();
        boolean verify = verify(signBytes);
        assertTrue(verify);
    }

    private byte[] sign() throws Exception {
        Signature signature = Signature.getInstance("SM3withSM2");
        signature.initSign(privateKey);
        signature.update(INFO);
        return signature.sign();
    }

    private boolean verify(byte[] signBytes) throws Exception {
        Signature signature = Signature.getInstance("SM3withSM2");
        signature.initVerify(publicKey);
        signature.update(INFO);
        return signature.verify(signBytes);
    }
}