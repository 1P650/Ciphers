package Ciphers.StreamCiphers;

import Ciphers.Utils.BitUtil;


class HC256 extends StreamCipher {
    private HC256_algorithm HC_A;
    HC256(){
        HC_A = new HC256_algorithm();
        super.algorithm = HC_A;
        super.KeySize = 32;
        super.IV_Size = 32;

    }
    @Override
    public void setKey(byte[] key) {
        if (key == null || key.length!=getKeySize())
            throw new StreamCipherExeption(StreamCipherExeption.KEY_LEN, 256, 32);
        byte[] IV_save = HC_A == null ? null : HC_A.IV;
        HC_A = new HC256_algorithm(key,IV_save);
        super.algorithm = HC_A;
    }

    private class HC256_algorithm extends StreamCipher.StreamCipherAlgorithm{
        private int[] keyStream;
        private int[] P = new int[1024];
        private int[] Q = new int[1024];
        private int[] W = new int[2560];
        private byte[] key_save;

        HC256_algorithm(){
        }
        HC256_algorithm(byte[] key,byte[] IV){
         if(IV!= null) this.IV = IV;
         this.key_save = key;
         init(key);
        }

        private void init(byte[] key) {
           int[] key_32 = BitUtil.ByteArrays.byteArrayToIntArray(key);
           int[] vector_32 = BitUtil.ByteArrays.byteArrayToIntArray(IV == null ? new byte[32]:IV);

            System.arraycopy(key_32,0,W,0,8);
            System.arraycopy(vector_32,0,W,8,8);
            for (int i = 16; i < 2559; i++) {
                W[i] = f2(W[i-2]) + W[i-7] + f1(W[i-15]) + W[i-16] + i;
            }
            System.arraycopy(W,512,P,0,1024);
            System.arraycopy(W,1536, Q,0,1024);
            encryptWithNoOutput();
        }

        @Override
        byte[] crypt(byte[] input) {
            int whenToStop = BitUtil.Extend.extendToSize(input.length,32);
            keyStream = new int[whenToStop/4];
            for (int i = 0; i < whenToStop/4; i++) {
                int j = i & 0x400;
                if( (i& 0x800) < 0x400){
                    P[j] = P[j] + P[(j-10) & 0x3ff] + g1(P[(j-3) & 0x3ff],P[(j - 1023)&0x3ff]);
                    keyStream[i] = h1(P[(j-12)&0x3ff]) ^ P[j];
                }
                else{
                    Q[j] = Q[j] + Q[(j-10) & 0x3ff] + g2(Q[(j-3) & 0x3ff],Q[(j - 1023)&0x3ff]);
                    keyStream[i] = h2(Q[(j-12)&0x3ff]) ^ Q[j];
                }
            }
            byte[] keyStream_b = BitUtil.ByteArrays.intArrayToByteArray(keyStream);
            byte[] keyStream_len = new byte[input.length];
            System.arraycopy(keyStream_b,0,keyStream_len,0,input.length);
            BitUtil.Print.printHex(keyStream,true);
            return BitUtil.Operation.XOR(keyStream_len,input);
        }


        void encryptWithNoOutput()
        {
            for (int i = 0; i < 4096; i++) {
                int j = i & 0x3ff;
                if( (i& 0x800) < 0x400){
                    P[j] = P[j] + P[(j-10) & 0x3ff] + g1(P[(j-3) & 0x3ff],P[(j - 1023)& 0x3ff]);
                }
                else{
                    Q[j] = Q[j] + Q[(j-10) & 0x3ff] + g2(Q[(j-3) & 0x3ff],Q[(j - 1023)&0x3ff]);
                }

            }
        }
        private int f1(int x){
            return (BitUtil.Rotation.rotateR(x,7)) ^ (BitUtil.Rotation.rotateR(x,18)) ^ (x>>3);
        }

        private int f2(int x){
            return (BitUtil.Rotation.rotateR(x,17)) ^ (BitUtil.Rotation.rotateR(x,19)) ^ (x>>10);
        }

        private int g1(int x,int y){
            return ((BitUtil.Rotation.rotateR(x,10) ^ BitUtil.Rotation.rotateR(y,23)) + Q[(x^y) & 0x3ff]);
        }

        private int g2(int x,int y){
            return ((BitUtil.Rotation.rotateR(x,10) ^ BitUtil.Rotation.rotateR(y,23)) + P[(x^y) & 0x3ff]);
        }

        private int h1(int x){
            byte[] xi = BitUtil.ByteArrays.intToByteArray(x);
            return Q[xi[3] & 0xff] + Q[256 + (xi[2]&0xff)] + Q[512 + (xi[1]&0xff)] + Q[768 + (xi[0]&0xff)];
        }

        private int h2(int x){
                byte[] xi = BitUtil.ByteArrays.intToByteArray(x);
               return P[xi[3] & 0xff] + P[256 + (xi[2]&0xff)] + P[512 + (xi[1]&0xff)] + P[768 + (xi[0]&0xff)];

        }
    }
}
