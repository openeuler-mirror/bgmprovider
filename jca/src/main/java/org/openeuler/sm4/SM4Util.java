package org.openeuler.sm4;

/**
 * implement SM4  encryption and decryption
 */
public class SM4Util {

    private static final byte[] sbox = {-42, -112, -23, -2, -52, -31, 61, -73, 22, -74, 20, -62, 40, -5, 44, 5, 43, 103, -102, 118, 42, -66, 4, -61, -86, 68, 19, 38, 73, -122, 6, -103, -100, 66, 80, -12, -111, -17, -104, 122, 51, 84, 11, 67, -19, -49, -84, 98, -28, -77, 28, -87, -55, 8, -24, -107, -128, -33, -108, -6, 117, -113, 63, -90, 71, 7, -89, -4, -13, 115, 23, -70, -125, 89, 60, 25, -26, -123, 79, -88, 104, 107, -127, -78, 113, 100, -38, -117, -8, -21, 15, 75, 112, 86, -99, 53, 30, 36, 14, 94, 99, 88, -47, -94, 37, 34, 124, 59, 1, 33, 120, -121, -44, 0, 70, 87, -97, -45, 39, 82, 76, 54, 2, -25, -96, -60, -56, -98, -22, -65, -118, -46, 64, -57, 56, -75, -93, -9, -14, -50, -7, 97, 21, -95, -32, -82, 93, -92, -101, 52, 26, 85, -83, -109, 50, 48, -11, -116, -79, -29, 29, -10, -30, 46, -126, 102, -54, 96, -64, 41, 35, -85, 13, 83, 78, 111, -43, -37, 55, 69, -34, -3, -114, 47, 3, -1, 106, 114, 109, 108, 91, 81, -115, 27, -81, -110, -69, -35, -68, 127, 17, -39, 92, 65, 31, 16, 90, -40, 10, -63, 49, -120, -91, -51, 123, -67, 45, 116, -48, 18, -72, -27, -76, -80, -119, 105, -105, 74, 12, -106, 119, 126, 101, -71, -15, 9, -59, 110, -58, -124, 24, -16, 125, -20, 58, -36, 77, 32, 121, -18, 95, 62, -41, -53, 57, 72};
    private static final int[] CK = new int[]{462357, 472066609, 943670861, 1415275113, 1886879365, -1936483679, -1464879427, -993275175, -521670923, -66909679, 404694573, 876298825, 1347903077, 1819507329, -2003855715, -1532251463, -1060647211, -589042959, -117504499, 337322537, 808926789, 1280531041, 1752135293, -2071227751, -1599623499, -1128019247, -656414995, -184876535, 269950501, 741554753, 1213159005, 1684763257};
    private static final int[] FK = new int[]{-1548633402, 1453994832, 1736282519, -1301273892};
    private final int BLOCK_SIZE = 16;

    /**
     * τtrsform
     *
     * @param input input(a0,a1,a2,a3)
     * @return τ(input)=(sbox(a0),sbox(a1),sbox(a2),sbox(a3))
     */
    private int tau(int input) {
        int lowest8bit = sbox[input & 255] & 255;
        int second8bit = sbox[(input >> 8) & 255] & 255;
        int third8bit = sbox[(input >> 16) & 255] & 255;
        int highest8bit = sbox[(input >> 24) & 255] & 255;
        second8bit = second8bit << 8;
        third8bit = third8bit << 16;
        highest8bit = highest8bit << 24;
        return lowest8bit | second8bit | third8bit | highest8bit;
    }

    /**
     * L change
     *
     * @param input
     * @return
     */
    private int l(int input) {
        return input ^
                ((input << 2) | (input >>> 30)) ^
                ((input << 10) | (input >>> 22)) ^
                ((input << 18) | (input >>> 14)) ^
                ((input << 24) | (input >>> 8));
    }

    /**
     * L' change
     *
     * @param input
     * @return
     */
    private int _l(int input) {
        return input ^ ((input << 13) | (input >>> 19)) ^ ((input << 23) | (input >>> 9));
    }

    /**
     * T change
     *
     * @param input
     * @return
     */
    private int t(int input) {
        return l(tau(input));
    }

    /**
     * T' change
     *
     * @param input
     * @return
     */
    private int _t(int input) {
        return _l(tau(input));
    }

    /**
     * F function
     *
     * @param x0
     * @param x1
     * @param x2
     * @param x3
     * @param rk0
     * @return
     */
    private int f(int x0, int x1, int x2, int x3, int rk0) {
        return x0 ^ t(x1 ^ x2 ^ x3 ^ rk0);
    }

    /**
     * reverse
     *
     * @param x32
     * @param x33
     * @param x34
     * @param x35
     * @return
     */
    private byte[] reverse(int x32, int x33, int x34, int x35) {
        byte[] output = new byte[BLOCK_SIZE];
        reverse(x32, x33, x34, x35, output, 0);
        return output;
    }

    /**
     * reverse
     *
     * @param x32
     * @param x33
     * @param x34
     * @param x35
     * @param output
     * @param outputOffset
     */
    private void reverse(int x32, int x33, int x34, int x35, byte[] output, int outputOffset) {

        readInt(output, x35, outputOffset);
        readInt(output, x34, 4 + outputOffset);
        readInt(output, x33, 8 + outputOffset);
        readInt(output, x32, 12 + outputOffset);
    }

    /**
     * convert int to 4 bytes
     *
     * @param output
     * @param x
     * @param start
     */
    public void readInt(byte[] output, int x, int start) {
        output[start] = (byte) (x >>> 24);
        start++;
        output[start] = (byte) ((x << 8) >>> 24);
        start++;
        output[start] = (byte) ((x << 16) >>> 24);
        start++;
        output[start] = (byte) ((x << 24) >>> 24);
    }

    /**
     * convert 4 bytes to int
     *
     * @param bytes
     * @param start
     * @return
     */
    public int readByte(byte[] bytes, int start) {
        int res = 0;
        res |= ((int) bytes[start]) << 24;
        start++;
        res |= ((((int) bytes[start]) << 24) >>> 8);
        start++;
        res |= ((((int) bytes[start]) << 24) >>> 16);
        start++;
        res |= ((((int) bytes[start]) << 24) >>> 24);
        return res;
    }

    /**
     * calculate rk
     *
     * @param key
     * @return
     */
    private int[] expandKey(byte[] key) {

        int[] rk = new int[32];

        int K0 = readByte(key, 0) ^ FK[0];
        int K1 = readByte(key, 4) ^ FK[1];
        int K2 = readByte(key, 8) ^ FK[2];
        int K3 = readByte(key, 12) ^ FK[3];

        for (int i = 0; i < rk.length; i++) {
            rk[i] = K0 ^ _t(K1 ^ K2 ^ K3 ^ CK[i]);
            K0 = K1;
            K1 = K2;
            K2 = K3;
            K3 = rk[i];
        }
        return rk;
    }

    /**
     * SM4 encrypt
     *
     * @param key
     * @param input
     * @return
     */
    public byte[] encrypt(byte[] key, byte[] input) {
        byte[] res = new byte[BLOCK_SIZE];
        encrypt(key, input, 0, res, 0);
        return res;
    }

    /**
     * SM4 encrypt
     *
     * @param key
     * @param input
     * @param inputOffset
     * @return
     */
    public byte[] encrypt(byte[] key, byte[] input, int inputOffset) {
        byte[] res = new byte[BLOCK_SIZE];
        encrypt(key, input, inputOffset, res, 0);
        return res;
    }

    /**
     * SM4 encrypt
     *
     * @param key
     * @param input
     * @param inputOffset
     * @param output
     * @param outputOffset
     */
    public void encrypt(byte[] key, byte[] input, int inputOffset, byte[] output, int outputOffset) {
        int[] rk = expandKey(key);
        int x0 = readByte(input, inputOffset);
        int x1 = readByte(input, 4 + inputOffset);
        int x2 = readByte(input, 8 + inputOffset);
        int x3 = readByte(input, 12 + inputOffset);

        for (int i = 0; i < rk.length; i++) {
            int res = f(x0, x1, x2, x3, rk[i]);
            x0 = x1;
            x1 = x2;
            x2 = x3;
            x3 = res;
        }

        reverse(x0, x1, x2, x3, output, outputOffset);
    }

    /**
     * SM4 decrypt
     *
     * @param key
     * @param cipherText
     * @return
     */
    public byte[] decrypt(byte[] key, byte[] cipherText) {
        byte[] res = new byte[BLOCK_SIZE];
        decrypt(key, cipherText, 0, res, 0);
        return res;
    }

    /**
     * SM4 decrypt
     *
     * @param key
     * @param input
     * @param inputOffset
     * @return
     */
    public byte[] decrypt(byte[] key, byte[] input, int inputOffset) {
        byte[] res = new byte[BLOCK_SIZE];
        decrypt(key, input, inputOffset, res, 0);
        return res;
    }

    /**
     * SM4 decrypt
     *
     * @param key
     * @param input
     * @param inputOffset
     * @param output
     * @param outputOffset
     */
    public void decrypt(byte[] key, byte[] input, int inputOffset, byte[] output, int outputOffset) {
        int[] rk = expandKey(key);

        int x0 = readByte(input, inputOffset);
        int x1 = readByte(input, 4 + inputOffset);
        int x2 = readByte(input, 8 + inputOffset);
        int x3 = readByte(input, 12 + inputOffset);

        for (int i = rk.length - 1; i >= 0; i--) {

            int res = f(x0, x1, x2, x3, rk[i]);
            x0 = x1;
            x1 = x2;
            x2 = x3;
            x3 = res;

        }
        reverse(x0, x1, x2, x3, output, outputOffset);
    }


    /**
     * xor operation
     *
     * @param b1
     * @param b2
     * @return the result of XOR of the shorter array and the corresponding part of the longer array
     */
    public byte[] xor(byte[] b1, byte[] b2) {
        if (b1 == null || b2 == null) {
            return null;
        }
        byte[] res = new byte[b1.length < b2.length ? b1.length : b2.length];
        for (int i = 0; i < res.length; i++) {
            res[i] = (byte) (b1[i] ^ b2[i]);
        }
        return res;
    }

    /**
     * xor operation
     *
     * @param b1
     * @param from1 b1's start index
     * @param len1
     * @param b2
     * @param from2 b2's start index
     * @param len2
     * @return the result of XOR of the shorter array and the corresponding part of the longer array
     */
    public byte[] xor(byte[] b1, int from1, int len1, byte[] b2, int from2, int len2) {
        if (b1 == null || b2 == null) {
            return null;
        }
        byte[] res = new byte[len1 < len2 ? len1 : len2];
        for (int i = 0; i < res.length; i++) {
            res[i] = (byte) (b1[i + from1] ^ b2[i + from2]);
        }
        return res;
    }

    /**
     * xor operation
     *
     * @param b1
     * @param b2
     * @return 16 bytes result of b1 xor b2 if b1.length<16 when i>b1.length res[i]= b2[i]^0;
     */
    public byte[] xor16Byte(byte[] b1, byte[] b2) {
        if (b1 == null || b2 == null) {
            return null;
        }
        if (b1.length != 16 && b2.length != 16) {
            return null;
        }
        byte[] res = new byte[16];
        int len = b1.length < b2.length ? b1.length : b2.length;
        for (int i = 0; i < len; i++) {
            res[i] = (byte) (b1[i] ^ b2[i]);
        }
        if (b1.length != b2.length) {
            int longLen = len == b1.length ? b2.length : b1.length;
            byte[] longArr = longLen == b1.length ? b1 : b2;
            for (int i = len; i < longLen; i++) {
                res[i] = (byte) (longArr[i] ^ 0);
            }
        }
        return res;
    }

    /**
     * copy the input from inputOffset into the output
     *
     * @param input
     * @param inputOffset
     * @param inputLen
     * @param output
     * @param outputOffset
     */
    public static void copyArray(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) {
        for (int i = inputOffset; i < inputOffset + inputLen; i++) {
            output[outputOffset++] = input[i];
        }
    }

}
