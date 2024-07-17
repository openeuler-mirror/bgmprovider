package org.openeuler;

import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Setup;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class SM4GCMBenchmark extends BaseBenchmark {

    private static final int SET_SIZE = 1024;
    private byte[][] data;
    private int index = 0;

    @Param({"SM4/GCM/NoPadding"})
    private String algorithm;

    @Param({"128"})
    private int keyLength;

    @Param({"" + 1024,
            "" + 10 * 1024,
            "" + 100 * 1024,
            "" + 1024 * 1024})
    private int dataSize;

    private byte[][] ivData;

    private byte[][] encryptedData;

    private Cipher decryptCipher;

    private SecretKeySpec ks;

    @Setup
    public void setup() throws Exception {
        super.setUp();

        byte[] keyBytes = fillRandom(new byte[keyLength / 8]);
        ks = new SecretKeySpec(keyBytes, "SM4");
        ivData = new byte[SET_SIZE][dataSize];
        data = fillRandom(new byte[SET_SIZE][dataSize]);
        encryptedData = new byte[SET_SIZE][dataSize];
        fillEncrypted(data, ivData, encryptedData);
    }

    @Benchmark
    public void encrypt() throws Exception {
        encryptTest();
    }

    @Benchmark
    @Fork(jvmArgsPrepend = {"-Djce.useLegacy=true"})
    public void encryptLegacy() throws Exception {
        encryptTest();
    }

    @Benchmark
    public void decrypt() throws Exception {
        decryptTest();
    }

    @Benchmark
    @Fork(jvmArgsPrepend = {"-Djce.useLegacy=true"})
    public void decryptLegacy() throws Exception {
        decryptTest();
    }

    private void encryptTest() throws Exception {
        byte[] d = data[index];
        index = (index + 1) % SET_SIZE;
        Cipher encryptCipher = (provider == null) ? Cipher.getInstance(algorithm) : Cipher.getInstance(algorithm, provider);
        encryptCipher.init(Cipher.ENCRYPT_MODE, ks);
        encryptCipher.doFinal(d);
    }

    public byte[] decryptTest() throws Exception {
        byte[] e = encryptedData[index];
        byte[] iv = ivData[index];
        index = (index + 1) % SET_SIZE;
        Cipher decryptCipher = (provider == null) ? Cipher.getInstance(algorithm) : Cipher.getInstance(algorithm, provider);
        decryptCipher.init(Cipher.DECRYPT_MODE, ks, new IvParameterSpec(iv));
        return decryptCipher.doFinal(e);
    }


    private void fillEncrypted(byte[][] data, byte[][] ivData, byte[][] encryptedData)
            throws Exception {
        for (int i = 0; i < encryptedData.length; i++) {
            Cipher encryptCipher = (provider == null) ? Cipher.getInstance(algorithm)
                    : Cipher.getInstance(algorithm, provider);
            encryptCipher.init(Cipher.ENCRYPT_MODE, ks);
            ivData[i] = encryptCipher.getIV();
            encryptedData[i] = encryptCipher.doFinal(data[i]);
        }
    }
}
