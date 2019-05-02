package Basic;

public class algorithmUtil {

    public static void reverseArray(byte[] input) {
        byte tmp;
        for (int i = 0; i < input.length >> 1; ++i) {
            tmp = input[i];
            input[i] = input[input.length - i - 1];
            input[input.length - i - 1] = tmp;
        }

    }
    public static void reverseArray(short[] input) {
        short tmp;
        for (int i = 0; i < input.length >> 1; ++i) {
            tmp = input[i];
            input[i] = input[input.length - i - 1];
            input[input.length - i - 1] = tmp;
        }

    }
    public static void reverseArray(int[] input) {
        int tmp;
        for (int i = 0; i < input.length >> 1; ++i) {
            tmp = input[i];
            input[i] = input[input.length - i - 1];
            input[input.length - i - 1] = tmp;
        }

    }
    public static void reverseArray(long[] input) {
        long tmp;
        for (int i = 0; i < input.length >> 1; ++i) {
            tmp = input[i];
            input[i] = input[input.length - i - 1];
            input[input.length - i - 1] = tmp;
        }

    }
    public static void reverseArray(char[] input) {
        char tmp;
        for (int i = 0; i < input.length >> 1; ++i) {
            tmp = input[i];
            input[i] = input[input.length - i - 1];
            input[input.length - i - 1] = tmp;
        }

    }
    public static void reverseArray(double [] input) {
        double tmp;
        for (int i = 0; i < input.length >> 1; ++i) {
            tmp = input[i];
            input[i] = input[input.length - i - 1];
            input[input.length - i - 1] = tmp;
        }

    }
    public static void reverseArray(float [] input) {
        float tmp;
        for (int i = 0; i < input.length >> 1; ++i) {
            tmp = input[i];
            input[i] = input[input.length - i - 1];
            input[input.length - i - 1] = tmp;
        }

    }
    public static void reverseArray(boolean [] input) {
        boolean tmp;
        for (int i = 0; i < input.length >> 1; ++i) {
            tmp = input[i];
            input[i] = input[input.length - i - 1];
            input[input.length - i - 1] = tmp;
        }

    }
    public static <Type> void reverseArray(Type[] input) {
        Type tmp;
        for (int i = 0; i < input.length >> 1; ++i) {
            tmp = input[i];
            input[i] = input[input.length - i - 1];
            input[input.length - i - 1] = tmp;
        }
    }


    public static void reverseMatrix(byte[][] input){
        byte[] tmp;
        for (int i = 0; i < input.length >> 1; ++i) {
            tmp = input[i];
            input[i] = input[input.length - i - 1];
            input[input.length - i - 1] = tmp;
        }
    }
    public static void reverseMatrix(short[][] input){
        short[] tmp;
        for (int i = 0; i < input.length >> 1; ++i) {
            tmp = input[i];
            input[i] = input[input.length - i - 1];
            input[input.length - i - 1] = tmp;
        }
    }
    public static void reverseMatrix(int[][] input){
        int[] tmp;
        for (int i = 0; i < input.length >> 1; ++i) {
            tmp = input[i];
            input[i] = input[input.length - i - 1];
            input[input.length - i - 1] = tmp;
        }
    }
    public static void reverseMatrix(long[][] input){
        long[] tmp;
        for (int i = 0; i < input.length >> 1; ++i) {
            tmp = input[i];
            input[i] = input[input.length - i - 1];
            input[input.length - i - 1] = tmp;
        }
    }
    public static void reverseMatrix(float[][] input){
        float[] tmp;
        for (int i = 0; i < input.length >> 1; ++i) {
            tmp = input[i];
            input[i] = input[input.length - i - 1];
            input[input.length - i - 1] = tmp;
        }
    }
    public static void reverseMatrix(double[][] input){
        double[] tmp;
        for (int i = 0; i < input.length >> 1; ++i) {
            tmp = input[i];
            input[i] = input[input.length - i - 1];
            input[input.length - i - 1] = tmp;
        }
    }
    public static void reverseMatrix(char[][] input){
        char[] tmp;
        for (int i = 0; i < input.length >> 1; ++i) {
            tmp = input[i];
            input[i] = input[input.length - i - 1];
            input[input.length - i - 1] = tmp;
        }
    }
    public static void reverseMatrix(boolean[][] input){
        boolean[] tmp;
        for (int i = 0; i < input.length >> 1; ++i) {
            tmp = input[i];
            input[i] = input[input.length - i - 1];
            input[input.length - i - 1] = tmp;
        }
    }
    public static <Type> void reverseMatrix(Type[][] input){
        Type[] tmp;
        for (int i = 0; i < input.length >> 1; ++i) {
            tmp = input[i];
            input[i] = input[input.length - i - 1];
            input[input.length - i - 1] = tmp;
        }
    }


    public static int indexOfElement(byte[] input, byte element){
        for (int i = 0; i < input.length; i++) {
            if(input[i] == element) return i;
        }
        return -1;
    }
    public static int indexOfElement(short[] input, short element){
        for (int i = 0; i < input.length; i++) {
            if(input[i] == element) return i;
        }
        return -1;
    }
    public static int indexOfElement(int[] input, int element){
        for (int i = 0; i < input.length; i++) {
            if(input[i] == element) return i;
        }
        return -1;
    }
    public static int indexOfElement(long[] input, long element){
        for (int i = 0; i < input.length; i++) {
            if(input[i] == element) return i;
        }
        return -1;
    }
    public static int indexOfElement(float[] input, float element){
        for (int i = 0; i < input.length; i++) {
            if(input[i] == element) return i;
        }
        return -1;
    }
    public static int indexOfElement(double[] input, double element){
        for (int i = 0; i < input.length; i++) {
            if(input[i] == element) return i;
        }
        return -1;
    }
    public static int indexOfElement(char[] input, char element){
        for (int i = 0; i < input.length; i++) {
            if(input[i] == element) return i;
        }
        return -1;
    }
    public static int indexOfElement(boolean[] input, boolean element){
        for (int i = 0; i < input.length; i++) {
            if(input[i] == element) return i;
        }
        return -1;
    }
    public static <Type> int indexOfElement(Type[] input, Type element){
        for (int i = 0; i < input.length; i++) {
            if(input[i] == element) return i;
        }
        return -1;
    }











}
