package Ciphers.StreamCiphers;

import Ciphers.Utils.BitUtil;

class Trivium extends StreamCipher {
    private Trivium_algorithm TRIVIUM_A;

    Trivium() {
        TRIVIUM_A = new Trivium_algorithm();
        super.algorithm = TRIVIUM_A;
        super.KeySize = 10;
        super.IV_Size = 10;
    }

    @Override
    public void setKey(byte[] key) {
        if (key == null || key.length != getKeySize())
            throw new StreamCipherExeption(StreamCipherExeption.KEY_LEN, 80, 10);
        TRIVIUM_A = new Trivium_algorithm(key);
        super.algorithm = TRIVIUM_A;
    }

    private class Trivium_algorithm extends StreamCipherAlgorithm {
        private byte[] innerState = new byte[288];
        Trivium_algorithm() {

        }

        Trivium_algorithm(byte[] key) {
           byte[] binaryKey = new byte[80];
           for(int i = 0,j=0; i < 80; i+=8,j++){
               byte[] b_c = BitUtil.Binary.byteToBinary(key[j]);
               byte[] b_c_8 = new byte[8];
               System.arraycopy(b_c,0,b_c_8,b_c_8.length - b_c.length, b_c.length);
               System.arraycopy(b_c_8,0,binaryKey,i,8);
           }
           byte[] binaryIV = new byte[80];
           if(IV!=null){
               for(int i = 0,j=0; i < 80; i+=8,j++){
                   byte[] b_c = BitUtil.Binary.byteToBinary(IV[j]);
                   byte[] b_c_8 = new byte[8];
                   System.arraycopy(b_c,0,b_c_8,b_c_8.length - b_c.length, b_c.length);
                   System.arraycopy(b_c_8,0,binaryKey,i,8);
               }
           }

           System.arraycopy(binaryKey,0,innerState,0,80);
           System.arraycopy(binaryIV,0,innerState,93,80);
           System.arraycopy(new byte[]{1,1,1},0,innerState,285,3);
            for (int i = 0; i < 1152; i++) {
                byte t1 = (byte) (innerState[65] ^ innerState[90] & innerState[91] ^ innerState[92] ^ innerState[170]);
                byte t2 = (byte) (innerState[161] ^ innerState[174] & innerState[175] ^ innerState[176] ^ innerState[263]);
                byte t3 = (byte) (innerState[242] ^ innerState[285] & innerState[286] ^ innerState[287] ^ innerState[68]);
                byte[] t1_bin = new byte[93];
                byte[] t2_bin = new byte[83];
                byte[] t3_bin = new byte[110];
                System.arraycopy(innerState,0,t1_bin,1,91);
                t1_bin[0] = t3;
                System.arraycopy(innerState,94,t2_bin,1,81);
                t2_bin[0] = t1;
                System.arraycopy(innerState,178,t3_bin,1,109);
                t3_bin[0] = t2;

                System.arraycopy(t1_bin,0,innerState,0,t1_bin.length);
                System.arraycopy(t2_bin,0,innerState,t1_bin.length,t2_bin.length);
                System.arraycopy(t3_bin,0,innerState,t1_bin.length + t2_bin.length,t3_bin.length);
            }
        }



        @Override
        byte[] crypt(byte[] input) {
            byte[] gamma = generateGamma(input.length * 8);
            return BitUtil.Operation.XOR(input,gamma);
        }

        private byte[] generateGamma(int len) {
            byte[] binary_gamma = new byte[len];
            int j = 0;
            for (int i = 0; i < len; i++) {
                byte t1 = (byte) (innerState[65] ^ innerState[92]);
                byte t2 = (byte) (innerState[161] ^ innerState[176]);
                byte t3 = (byte) (innerState[242] ^ innerState[287]);
                byte z = (byte) (t1^t2^t3);
                binary_gamma[i] = z;
                byte[] t1_bin = new byte[93];
                byte[] t2_bin = new byte[83];
                byte[] t3_bin = new byte[110];
                System.arraycopy(innerState,0,t1_bin,1,91);
                t1_bin[0] = t3;
                System.arraycopy(innerState,94,t2_bin,1,81);
                t2_bin[0] = t1;
                System.arraycopy(innerState,178,t3_bin,1,109);
                t3_bin[0] = t2;
                System.arraycopy(t1_bin,0,innerState,0,t1_bin.length);
                System.arraycopy(t2_bin,0,innerState,t1_bin.length,t2_bin.length);
                System.arraycopy(t3_bin,0,innerState,t1_bin.length + t2_bin.length,t3_bin.length);
            }
            byte[] gamma = new byte[len / 8];
            for (int i = 0,q=0; i < len; i+=8,q++) {
                byte[] current_bit = new byte[8];
                System.arraycopy(binary_gamma,i,current_bit,0,8);
                byte current_byte = BitUtil.Binary.binaryToByte(current_bit);
                gamma[q] = current_byte;
            }
            return gamma;
        }
    }
}
