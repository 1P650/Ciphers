package Ciphers.HashFunctions.SHA1;

import Ciphers.Basic.HashFunction;
import Ciphers.Utils.BitUtil;

public class SHA1 implements HashFunction {
    private int LENGTH = 40;
    private int h0 = 0x67452301;
    private int h1 = 0xEFCDAB89;
    private int h2 = 0x98BADCFE;
    private int h3 = 0x10325476;
    private int h4 = 0xC3D2E1F0;

    @Override
    public byte[] process(byte[] input) {
        byte[] input_prepared = padding_process(input);

        for (int i = 0; i < input_prepared.length; i += 64) {
            int[] words_32bit = new int[80];
            byte[] chunk = new byte[64];
            System.arraycopy(input_prepared, i, chunk, 0, chunk.length);
            int[] chunk_L = BitUtil.ByteArrays.byteArrayToIntArray(chunk);
            System.arraycopy(chunk_L, 0, words_32bit, 0, chunk_L.length);

            for (int j = 16; j < 80; j++) {
                words_32bit[j] = BitUtil.BitRotation.rotateL(words_32bit[j - 3] ^ words_32bit[j - 8] ^ words_32bit[j - 14] ^ words_32bit[j - 16],1);
            }
            int a = h0;
            int b = h1;
            int c = h2;
            int d = h3;
            int e = h4;

            for (int j = 0; j < 80; j++) {
                int f,k;
                if (j <= 19) {
                    f = (b & c) | ((~b) & d);
                    k = 0x5A827999;
                } else if (j <= 39) {
                    f = b ^ c ^ d;
                    k = 0x6ED9EBA1;
                } else if ( j <= 59) {
                    f = (b & c) | (b & d) | (c & d);
                    k = 0x8F1BBCDC;
                } else {
                    f = b ^ c ^ d;
                    k = 0xCA62C1D6;
                }

               int temp = BitUtil.BitRotation.rotateL(a,5) + f + e + k + words_32bit[j];
                e = d;
                d = c;
                c = BitUtil.BitRotation.rotateL(b,30);
                b = a;
                a = temp;
            }
            h0 = h0 + a;
            h1 = h1 + b;
            h2 = h2 + c;
            h3 = h3 + d;
            h4 = h4 + e;

        }
        byte[] hash = BitUtil.ByteArrays.intArrayToByteArray(
                new int[]{
                        h0,
                        h1,
                        h2,
                        h3,
                        h4,
                });
        this.reset();
        return hash;
    }

    @Override
    public void reset() {
       this.h0 = 0x67452301;
       this.h1 = 0xEFCDAB89;
       this.h2 = 0x98BADCFE;
       this.h3 = 0x10325476;
       this.h4 = 0xC3D2E1F0;
    }

    @Override
    public int getLength() {
        return LENGTH;
    }

    private byte[] padding_process(byte[] input) {
        int l_orig = input.length;
        int l = l_orig << 3;
        int k = 2;
        while ((l + k) % 512 != 448) k++;
        l += k + 64;
        byte[] prepared = new byte[l >> 3];
        System.arraycopy(input, 0, prepared, 0, l_orig);
        prepared[l_orig] = (byte) 0b10000000;
        byte[] coping = BitUtil.ByteArrays.intToByteArray(l_orig << 3);
        System.arraycopy(coping, 0, prepared, prepared.length - coping.length, coping.length);
        return prepared;
    }
}
