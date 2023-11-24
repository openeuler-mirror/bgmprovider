package org.openeuler.sm4;

import java.util.Arrays;

/**
 * tools of GCM mode
 */
public class GMacUtil {
    private static SM4Util sm4 = new SM4Util();

    /**
     * calculate CTR0 according to iv
     * @param iv iv
     * @param H The result of encrypting the all-zero input
     * @return CTR0
     */
    public static byte[] getCounter0(byte[] iv,byte[] H) {
        byte[] counter = null;
        if (iv.length == 12) {
            counter = new byte[16];
            for (int i = 0; i < iv.length; i++) {
                counter[i] = iv[i];
            }
            counter[15] = 1;
        } else {
                int s= 16-iv.length;
                counter = new byte[iv.length+s+16];
                sm4.copyArray(iv,0, iv.length, counter,0);
                counter[counter.length-1]= (byte) (iv.length*8);
                counter = GHASH(counter,H);
        }
        return counter;
    }

    /**
     * GHASH function refer to: nistspecialpublication800-38d
     * @param x
     * @param H
     * @return
     */
    public static byte[] GHASH(byte[] x,byte[] H) {
        byte[] y = new byte[16];
        for (int i = 0; i < x.length; i += 16) {
            y=sm4.xor(y, Arrays.copyOfRange(x,i,i+16));
            y=mult(y,H);
        }
        return y;
    }

    /**
     * Multiplication Operation on Blocks refer to: nistspecialpublication800-38d
     * @param x
     * @param y
     * @return
     */
    public static byte[] mult(byte[] x,byte[] y){
        byte[] Z = new byte[16];
        byte[] V = new byte[16];
        byte[] R = new byte[16];
        R[0] = (byte) 0xe1;
        sm4.copyArray(y,0,y.length,V,0);
        for (int i = 0; i < 128; i++) {
            if( (x[i/8]&(1<<(7-(i%8)))) !=0){
                Z= sm4.xor(Z,V);
            }
            if((V[15]&1)!=0){
                V = sm4.xor(moveRightOneBit(V),R);
            }else{
                V = moveRightOneBit(V);
            }
        }
        return Z;
    }

    /**
     * shifts the 16-byte byte array one bit to the right
     * @param input
     * @return
     */
    public static byte[] moveRightOneBit(byte[] input){
        byte[] res = new byte[input.length];
        for (int i = 0; i < input.length; i++) {
            res[i] = (byte) (input[i]>>1);
            if(i==0){
                res[i] &=(byte)0x7f;
            }
            else{
                int lsb = (input[i-1]&1)==1?1:0;
                if(lsb==1){
                    res[i] |=(byte)0x80;
                }else {
                    res[i] &=(byte)0x7f;
                }
            }
        }
        return res;
    }


}

