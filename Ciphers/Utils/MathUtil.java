package Ciphers.Utils;

public final class MathUtil {
    public static class Operation {
        public static int MultiplicativeInverse(int a, int m) {
            int m0 = m;
            int y = 0, x = 1;
            if (m == 1)
                return 0;
            while (a > 1) {
                int q = a / m;
                int t = m;
                m = a % m;
                a = t;
                t = y;
                y = x - q * y;
                x = t;
            }
            if (x < 0)
                x += m0;
            return x;
        }

        public static int AdditiveInverse(int x, int n) {
            return ((n - x) % n);
        }

        public static int Multiply_16(int a, int b) {
            a &= 0xFFFF;
            b &= 0xFFFF;
            int p;
            if (a != 0) {
                if (b != 0) {
                    p = a * b;
                    b = (p & 0xFFFF);
                    a = (p >>> 16);
                    return (b - a + (b < a ? 1 : 0));
                } else {
                    return 1 - a;
                }
            } else
                return 1 - b;
        }

        public static int Add_16(int a, int b) {
            return (a + b) & 0xFFFF;
        }

        public static int Add_32(int a,int b){
            return (int) (((long) a + (long)b) % (0x100000000L));
        }

        public static int Sub_32(int a, int b){
            if( b <= a ) {
                return a - b;
            }

            return (int) (((0x100000000L) + a ) - b);
        }
    }
}
