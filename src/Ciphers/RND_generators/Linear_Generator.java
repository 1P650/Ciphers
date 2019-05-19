package Ciphers.RND_generators;

import Ciphers.Basic.PRN_generator;
import Ciphers.Utils.BitUtil;

public class Linear_Generator implements PRN_generator {
    private long next = 0;
    @Override
    public void setSeed(byte[] seed) {
          this.next = BitUtil.ByteArrays.byteArrayToLong(seed);
    }
    public void setSeed(long seed){
       this.next = seed;
    }


    private byte[] nextRandom() {
        this.next = (next * 0xCB971DFA23CB971DL + 0xC62532BC62532BL) % 0x7fffffffffffffffL;
        return BitUtil.ByteArrays.longToByteArray(next);
    }

    @Override
    public byte[] nextBytes(byte[] bytes) {
        byte[] a = new byte[bytes.length];
        byte flag = 0x1;
        for (int i = 0; i < bytes.length>>3; i+=8) {
            byte[] chuck = this.nextRandom();
            System.arraycopy(chuck,0,a,i,chuck.length);
        }
        if(flag==0x1){byte[] chuck = this.nextRandom(); System.arraycopy(chuck,0,a,a.length-8,chuck.length);}
        return a;

    }

    @Override
    public void reset() {
        this.next = 0;
    }
}
