package Basic;

public class bitUtil {
    private static final int BYTE_BITSIZE = 8;
    private static final int SHORT_BITSIZE = 16;
    private static final int INT_BITSIZE = 32;
    private static final int LONG_BITSIZE = 64;

    public static long rotateR(long i, long bits) {
        return ((i >>> bits) | (i << (LONG_BITSIZE - bits)));
    }

    public static long rotateL(long i, long bits) {
        return ((i << bits) | (i >>> (LONG_BITSIZE - bits)));
    }

    public static int rotateR(int i, int bits) {
        return ((i >>> bits) | (i << (INT_BITSIZE - bits)));
    }

    public static int rotateL(int i, int bits) {
        return ((i << bits) | (i >>> (INT_BITSIZE - bits)));
    }


    public short rotateR(short i, int bits) {
        return (short) ((i >>> bits) | (i << (SHORT_BITSIZE - bits)));
    }

    public static short rotateL(short i, int bits) {
        return (short) ((i << bits) | (i >>> (SHORT_BITSIZE - bits)));
    }

    public static byte rotateR(byte i, int bits) {
        return (byte) ((i >>> bits) | (i << (BYTE_BITSIZE - bits)));

    }

    public static byte rotateL(byte i, int bits) {
        return (byte) ((i << bits) | (i >>> (BYTE_BITSIZE - bits)));
    }

    public static long byteArrayToLong(byte[] b) {

        long l = b[0] & 0xff;
        l = (l << 8) ^ (long) b[1] & 0xff;
        l = (l << 8) ^ (long) b[2] & 0xff;
        l = (l << 8) ^ (long) b[3] & 0xff;
        l = (l << 8) ^ (long) b[4] & 0xff;
        l = (l << 8) ^ (long) b[5] & 0xff;
        l = (l << 8) ^ (long) b[6] & 0xff;
        l = (l << 8) ^ (long) b[7] & 0xff;

        return l;
    }

    public static byte[] longToByteArray(long l) {
        return new byte[]{
                (byte) (l >> 56),
                (byte) (l >> 48),
                (byte) (l >> 40),
                (byte) (l >> 32),
                (byte) (l >> 24),
                (byte) (l >> 16),
                (byte) (l >> 8),
                (byte) l
        };
    }

    public static long[] byteArrayToLongArray(byte[] b) {
        long[] l = new long[b.length>>3];


        for (int i = 0,j=0; i < b.length; i+=8,j++) {
            byte[] chunk = new byte[8];
            System.arraycopy(b,i,chunk,0,chunk.length);
            l[j] = byteArrayToLong(chunk);

        }
        return l;
    }

    public static byte[] longArrayToByteArray(long[] l) {
        byte[] b = new byte[l.length<<3];
        int padding_t = 0;
        for (int i = 0; i < l.length; i++) {
            byte[] chunk = bitUtil.longToByteArray(l[i]);
            System.arraycopy(chunk,0,b,i+padding_t,chunk.length);
            padding_t+=chunk.length-1;

        }
        return b;
    }

    public static void printHex_byteArray(byte[] input){
        for (byte b:input) {
            System.out.printf("%x",b);
        }
        System.out.println();
    }



}
