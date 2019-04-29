ppackage RND_generators;

import Basic.PRN_generator;
import Basic.bitUtil;


public class ISAAC implements PRN_generator {
    int[] internalState = new int[256];
    int a = 0, b = 0, c = 0;

    @Override
    public void setSeed(byte[] seed) {
        this.internalState = bitUtil.byteArrayToIntArray(mix(extend(seed)));

    }

    @Override
    public byte[] nextBytes(byte[] in) {
        int[] out = new int[256];
        c += 1;
        b += c;
        int x = 0;
        for (int i = 0; i < 256; i++) {
            x = internalState[i];
            a = f(a, i) + internalState[(i + 128) % 256];
            internalState[i] = a + b + internalState[(x >>> 2) % 256];
            out[i] = x + internalState[(i >>> 10) % 256];
            b = out[i];
        }
        byte[] copy = bitUtil.intArrayToByteArray(out);
        byte[] retq = new byte[in.length];
        System.arraycopy(copy,0,retq,0,retq.length);
        return retq;
    }

    private int f(int n, int i) {
        switch (i % 4) {
            case 1:
                return n >> 6;
            case 2:
                return n << 2;
            case 3:
                return n >> 16;
            default:
                return n << 13;
        }
    }

    private static byte[] extend(byte[] bytes) {
        byte[] repeat = new byte[1024];
        for (int i = 0; i < repeat.length; i += bytes.length) {
            System.arraycopy(bytes, 0, repeat, (i + bytes.length > repeat.length ? repeat.length - i : i), bytes.length);
        }
        return repeat;

    }

    private static byte[] mix(byte[] s) {
        for (int i = 0; i < s.length - 8; i += 8) {
            s[i] ^= s[i + 1] << 11;
            s[i + 3] += s[i];
            s[i + 1] += s[i + 2];
            s[i + 1] ^= s[i + 2] >>> 2;
            s[i + 4] += s[i + 1];
            s[i + 2] += s[i + 3];
            s[i + 2] ^= s[i + 3] << 8;
            s[i + 5] += s[i + 2];
            s[i + 3] += s[i + 4];
            s[i + 3] ^= s[i + 4] >>> 16;
            s[i + 6] += s[i + 3];
            s[i + 4] += s[i + 5];
            s[i + 4] ^= s[i + 5] << 10;
            s[i + 7] += s[i + 4];
            s[i + 5] += s[i + 6];
            s[i + 5] ^= s[i + 6] >>> 4;
            s[i + 8] += s[i + 5];
            s[i + 6] += s[i + 7];
            s[i + 6] ^= s[i + 7] << 8;
            s[i + 1] += s[i + 6];
            s[i + 7] += s[i];
            s[i + 7] ^= s[i] >>> 9;
            s[i + 2] += s[i + 7];
            s[i] += s[i + 1];
  
        }

        return s;
    }
    public void reset(){
        this.internalState = new int[256];
        this.a = 0;
        this.b = 0;
        this.c = 0;
    }
}
