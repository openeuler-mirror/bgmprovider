/*
 * Copyright (c) 2024, Huawei Technologies Co., Ltd. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Huawei designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Huawei in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please visit https://gitee.com/openeuler/bgmprovider if you need additional
 * information or have any questions.
 */

package org.openeuler.sm4;

import javax.crypto.BadPaddingException;

public class SM4Padding {

    //default
    String padding = "PKCS5PADDING";

    public String getPadding() {
        return padding;
    }

    public void setPadding(String padding) {
        this.padding = padding;
    }

    /**
     * fill the input data
     * @param input
     * @return
     */
    public byte[]  fill(byte[] input){
        //Calculate the number of bytes that need to be filled
        int need = (16-input.length%16);
        byte[] output = new byte[input.length+need];
        SM4Util.copyArray(input,0, input.length, output,0);
        for (int i = input.length;i< input.length+need;i++){
            output[i] = (byte)need;
        }
        return output;
    }

    /**
     *  fill the input data
     * @param input
     * @param offset start index of input
     * @param len
     * @return
     */
    public byte[] fill(byte[] input,int offset,int len){
        int need = (16-len%16);
        byte[] output = new byte[len+need];
       SM4Util.copyArray(input,offset, len,output,0 );
        for (int i=len;i< output.length;i++){
            output[i] = (byte)need;
        }
        return output;
    }

    /**
     * remove the filling
     * @param input
     * @return data before padding
     * @throws BadPaddingException
     */
    public byte[] recover(byte[] input) throws BadPaddingException {
      if(!isFilled(input)){
          throw new BadPaddingException();
      }
      int n = input[input.length-1];
      byte[] output = new byte[input.length-n];
      SM4Util.copyArray(input,0,output.length,output,0);
      return output;
    }

    /**
     * determine if the input data has been padded
     * @param input
     * @return
     */
    public boolean isFilled(byte[] input){
        int  n = input[input.length-1];
        for (int i = input.length-1; i >= input.length-n; i--) {
            if(input[i]!=(byte)n){
                return false;
            }
        }
        return true;
    }
}
