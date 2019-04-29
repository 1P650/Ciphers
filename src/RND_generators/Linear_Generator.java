package RND_generators;

import Basic.PRN_generator;
import Basic.bitUtil;

public class Linear_Generator implements PRN_generator {
    private long next = 0;
    @Override
    public void setSeed(byte[] seed) {
          this.next = bitUtil.byteArrayToLong(seed);
    }
    public void setSeed(long seed){
       this.next = seed;
    }


    private byte[] nextRandom() {
        next = (next * 0xCB971DFA23L + 0xC62532BL) % 0x7fffffffffffffffL;
        return bitUtil.longToByteArray(next);
    }

    @Override
    public byte[] nextBytes(byte[] bytes) {
        byte[] a = new byte[bytes.length];
        for (int i = 0; i < bytes.length>>3; i+=8) {
            byte[] chuck = this.nextRandom();
            System.arraycopy(chuck,0,a,i,chuck.length);
        }
        return a;

    }

    @Override
    public void reset() {
        this.next = 0;
    }
}
