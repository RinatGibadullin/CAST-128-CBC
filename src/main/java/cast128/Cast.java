package cast128;

import java.nio.ByteBuffer;

public class Cast {

    private byte[] key = new byte[16];
    private byte[] message = new byte[8];
    private byte[] crypto = new byte[8];

    public byte[] getPlaintext() {
        return plaintext;
    }

    private byte[] plaintext = new byte[8];

    private int[] S1 = SBox.S1;
    private int[] S2 = SBox.S2;
    private int[] S3 = SBox.S3;
    private int[] S4 = SBox.S4;
    private int[] S5 = SBox.S5;
    private int[] S6 = SBox.S6;
    private int[] S7 = SBox.S7;
    private int[] S8 = SBox.S8;

    private Key K = new Key();

    public byte[] getCrypto() {
        return crypto;
    }

    public void setCrypto(byte[] crypto) {
        this.crypto = crypto;
    }

    public Cast() {
    }

    Cast(byte[] key, byte[] message) throws Exception {
        if (key.length != 16 && message.length != 8)
            throw new Exception("Wrong key or message size !");
        else {
            this.key = key.clone();
            this.message = message.clone();
        }
    }

    private final int f1(int I, int m, int r) {
        I = m + I;
        I = I << r | I >>> (32 - r);
        return (((S1[(I >>> 24) & 0xFF])
                ^ S2[(I >>> 16) & 0xFF])
                - S3[(I >>> 8) & 0xFF])
                + S4[I & 0xFF];
    }

    private final int f2(int I, int m, int r) {
        I = m ^ I;
        I = I << r | I >>> (32 - r);
        return (((S1[(I >>> 24) & 0xFF])
                - S2[(I >>> 16) & 0xFF])
                + S3[(I >>> 8) & 0xFF])
                ^ S4[I & 0xFF];
    }

    private final int f3(int I, int m, int r) {
        I = m - I;
        I = I << r | I >>> (32 - r);
        return (((S1[(I >>> 24) & 0xFF])
                + S2[(I >>> 16) & 0xFF])
                ^ S3[(I >>> 8) & 0xFF])
                - S4[I & 0xFF];
    }

    public void makeKey() {
        int z0z1z2z3, z4z5z6z7, z8z9zAzB, zCzDzEzF;
        byte[] x = new byte[16];
        byte[] z = new byte[16];

        int b0 = ByteBuffer.wrap(key, 0, 4).getInt(); //меняет 4 байта из key на другие
        int b1 = ByteBuffer.wrap(key, 4, 4).getInt();
        int b2 = ByteBuffer.wrap(key, 8, 4).getInt();
        int b3 = ByteBuffer.wrap(key, 12, 4).getInt();

        for (int i = 0; i < 2; i++) {

            //b4
            z0z1z2z3 = b0 ^
                    S5[x[13] & 0xFF] ^
                    S6[x[15] & 0xFF] ^
                    S7[x[12] & 0xFF] ^
                    S8[x[14] & 0xFF] ^
                    S7[x[8] & 0xFF];
            unscramble(z0z1z2z3, z, 0, 4);

            z4z5z6z7 = b2 ^
                    S5[z[0] & 0xFF] ^
                    S6[z[2] & 0xFF] ^
                    S7[z[1] & 0xFF] ^
                    S8[z[3] & 0xFF] ^
                    S8[x[10] & 0xFF];
            unscramble(z4z5z6z7, z, 4, 8);

            z8z9zAzB = b3 ^
                    S5[z[7] & 0xFF] ^
                    S6[z[6] & 0xFF] ^
                    S7[z[5] & 0xFF] ^
                    S8[z[4] & 0xFF] ^
                    S5[x[9] & 0xFF];
            unscramble(z8z9zAzB, z, 8, 12);

            zCzDzEzF = b1 ^
                    S5[z[10] & 0xFF] ^
                    S6[z[9] & 0xFF] ^
                    S7[z[11] & 0xFF] ^
                    S8[z[8] & 0xFF] ^
                    S6[x[11] & 0xFF];
            unscramble(zCzDzEzF, z, 12, 16);

            K.setK(i * 16,
                    S5[z[8] & 0xFF] ^
                            S6[z[9] & 0xFF] ^
                            S7[z[7] & 0xFF] ^
                            S8[z[6] & 0xFF] ^
                            S5[z[2] & 0xFF]);
            K.setK(1 + i * 16,
                    S5[z[10] & 0xFF] ^
                            S6[z[11] & 0xFF] ^
                            S7[z[5] & 0xFF] ^
                            S8[z[4] & 0xFF] ^
                            S6[z[6] & 0xFF]);
            K.setK(2 + i * 16,
                    S5[z[12] & 0xFF] ^
                            S6[z[13] & 0xFF] ^
                            S7[z[3] & 0xFF] ^
                            S8[z[2] & 0xFF] ^
                            S7[z[9] & 0xFF]);
            K.setK(3 + i * 16,
                    S5[z[14] & 0xFF] ^
                            S6[z[15] & 0xFF] ^
                            S7[z[1] & 0xFF] ^
                            S8[z[0] & 0xFF] ^
                            S8[z[12] & 0xFF]);

            b0 = z8z9zAzB ^
                    S5[z[5] & 0xFF] ^
                    S6[z[7] & 0xFF] ^
                    S7[z[4] & 0xFF] ^
                    S8[z[6] & 0xFF] ^
                    S7[z[0] & 0xFF];
            unscramble(b0, x, 0, 4);

            b1 = z0z1z2z3 ^
                    S5[x[0] & 0xFF] ^
                    S6[x[2] & 0xFF] ^
                    S7[x[1] & 0xFF] ^
                    S8[x[3] & 0xFF] ^
                    S8[z[2] & 0xFF];
            unscramble(b1, x, 4, 8);

            b2 = z4z5z6z7 ^
                    S5[x[7] & 0xFF] ^
                    S6[x[6] & 0xFF] ^
                    S7[x[5] & 0xFF] ^
                    S8[x[4] & 0xFF] ^
                    S5[z[1] & 0xFF];
            unscramble(b2, x, 8, 12);

            b3 = zCzDzEzF ^
                    S5[x[10] & 0xFF] ^
                    S6[x[9] & 0xFF] ^
                    S7[x[11] & 0xFF] ^
                    S8[x[8] & 0xFF] ^
                    S6[z[3] & 0xFF];
            unscramble(b3, x, 12, 16);


            K.setK(4 + i * 16,
                    S5[x[3] & 0xFF] ^
                            S6[x[2] & 0xFF] ^
                            S7[x[12] & 0xFF] ^
                            S8[x[13] & 0xFF] ^
                            S5[x[8] & 0xFF]);
            K.setK(5 + i * 16,
                    S5[x[1] & 0xFF] ^
                            S6[x[0] & 0xFF] ^
                            S7[x[14] & 0xFF] ^
                            S8[x[15] & 0xFF] ^
                            S6[x[13] & 0xFF]);
            K.setK(6 + i * 16,
                    S5[x[7] & 0xFF] ^
                            S6[x[6] & 0xFF] ^
                            S7[x[8] & 0xFF] ^
                            S8[x[9] & 0xFF] ^
                            S7[x[3] & 0xFF]);
            K.setK(7 + i * 16,
                    S5[x[5] & 0xFF] ^
                            S6[x[4] & 0xFF] ^
                            S7[x[10] & 0xFF] ^
                            S8[x[11] & 0xFF] ^
                            S8[x[7] & 0xFF]);


            z0z1z2z3 = b0 ^
                    S5[x[13] & 0xFF] ^
                    S6[x[15] & 0xFF] ^
                    S7[x[12] & 0xFF] ^
                    S8[x[14] & 0xFF] ^
                    S7[x[8] & 0xFF];
            unscramble(z0z1z2z3, z, 0, 4);

            z4z5z6z7 = b2 ^
                    S5[z[0] & 0xFF] ^
                    S6[z[2] & 0xFF] ^
                    S7[z[1] & 0xFF] ^
                    S8[z[3] & 0xFF] ^
                    S8[x[10] & 0xFF];
            unscramble(z4z5z6z7, z, 4, 8);

            z8z9zAzB = b3 ^
                    S5[z[7] & 0xFF] ^
                    S6[z[6] & 0xFF] ^
                    S7[z[5] & 0xFF] ^
                    S8[z[4] & 0xFF] ^
                    S5[x[9] & 0xFF];
            unscramble(z8z9zAzB, z, 8, 12);

            zCzDzEzF = b1 ^
                    S5[z[10] & 0xFF] ^
                    S6[z[9] & 0xFF] ^
                    S7[z[11] & 0xFF] ^
                    S8[z[8] & 0xFF] ^
                    S6[x[11] & 0xFF];
            unscramble(zCzDzEzF, z, 12, 16);

            K.setK(8 + i * 16,
                    S5[z[3] & 0xFF] ^
                            S6[z[2] & 0xFF] ^
                            S7[z[12] & 0xFF] ^
                            S8[z[13] & 0xFF] ^
                            S5[z[9] & 0xFF]);
            K.setK(9 + i * 16,
                    S5[z[1] & 0xFF] ^
                            S6[z[0] & 0xFF] ^
                            S7[z[14] & 0xFF] ^
                            S8[z[15] & 0xFF] ^
                            S6[z[12] & 0xFF]);
            K.setK(10 + i * 16,
                    S5[z[7] & 0xFF] ^
                            S6[z[6] & 0xFF] ^
                            S7[z[8] & 0xFF] ^
                            S8[z[9] & 0xFF] ^
                            S7[z[2] & 0xFF]);
            K.setK(11 + i * 16,
                    S5[z[5] & 0xFF] ^
                            S6[z[4] & 0xFF] ^
                            S7[z[10] & 0xFF] ^
                            S8[z[11] & 0xFF] ^
                            S8[z[6] & 0xFF]);

            b0 = z8z9zAzB ^
                    S5[z[5] & 0xFF] ^
                    S6[z[7] & 0xFF] ^
                    S7[z[4] & 0xFF] ^
                    S8[z[6] & 0xFF] ^
                    S7[z[0] & 0xFF];
            unscramble(b0, x, 0, 4);

            b1 = z0z1z2z3 ^
                    S5[x[0] & 0xFF] ^
                    S6[x[2] & 0xFF] ^
                    S7[x[1] & 0xFF] ^
                    S8[x[3] & 0xFF] ^
                    S8[z[2] & 0xFF];
            unscramble(b1, x, 4, 8);

            b2 = z4z5z6z7 ^
                    S5[x[7] & 0xFF] ^
                    S6[x[6] & 0xFF] ^
                    S7[x[5] & 0xFF] ^
                    S8[x[4] & 0xFF] ^
                    S5[z[1] & 0xFF];
            unscramble(b2, x, 8, 12);

            b3 = zCzDzEzF ^
                    S5[x[10] & 0xFF] ^
                    S6[x[9] & 0xFF] ^
                    S7[x[11] & 0xFF] ^
                    S8[x[8] & 0xFF] ^
                    S6[z[3] & 0xFF];
            unscramble(b3, x, 12, 16);

            K.setK(12 + i * 16,
                    S5[x[8] & 0xFF] ^
                            S6[x[9] & 0xFF] ^
                            S7[x[7] & 0xFF] ^
                            S8[x[6] & 0xFF] ^
                            S5[x[3] & 0xFF]);
            K.setK(13 + i * 16,
                    S5[x[10] & 0xFF] ^
                            S6[x[11] & 0xFF] ^
                            S7[x[5] & 0xFF] ^
                            S8[x[4] & 0xFF] ^
                            S6[x[7] & 0xFF]);
            K.setK(14 + i * 16,
                    S5[x[12] & 0xFF] ^
                            S6[x[13] & 0xFF] ^
                            S7[x[3] & 0xFF] ^
                            S8[x[2] & 0xFF] ^
                            S7[x[8] & 0xFF]);
            K.setK(15 + i * 16,
                    S5[x[14] & 0xFF] ^
                            S6[x[15] & 0xFF] ^
                            S7[x[1] & 0xFF] ^
                            S8[x[0] & 0xFF] ^
                            S8[x[13] & 0xFF]);
        }
        K.setSubKeys();
    }

    public void encrypt() {
        byte[] result = new byte[8];

        int L = ByteBuffer.wrap(message, 0, 4).getInt();
        int R = ByteBuffer.wrap(message, 4, 4).getInt();

        L ^= f1(R, K.getKm(0), K.getKr(0));
        R ^= f2(L, K.getKm(1), K.getKr(1)); // round 2
        L ^= f3(R, K.getKm(2), K.getKr(2));
        R ^= f1(L, K.getKm(3), K.getKr(3)); // round 4
        L ^= f2(R, K.getKm(4), K.getKr(4));
        R ^= f3(L, K.getKm(5), K.getKr(5)); // round 6
        L ^= f1(R, K.getKm(6), K.getKr(6));
        R ^= f2(L, K.getKm(7), K.getKr(7)); // round 8
        L ^= f3(R, K.getKm(8), K.getKr(8));
        R ^= f1(L, K.getKm(9), K.getKr(9)); // round 10
        L ^= f2(R, K.getKm(10), K.getKr(10));
        R ^= f3(L, K.getKm(11), K.getKr(11)); // round 12
        L ^= f1(R, K.getKm(12), K.getKr(12));
        R ^= f2(L, K.getKm(13), K.getKr(13)); // round 14
        L ^= f3(R, K.getKm(14), K.getKr(14));
        R ^= f1(L, K.getKm(15), K.getKr(15)); // round 16

        unscramble(R, result, 0, 4);
        unscramble(L, result, 4, 8);

        crypto = result;
    }

    public void decrypt() {
        byte[] result = new byte[8];

        int L = ByteBuffer.wrap(crypto, 0, 4).getInt();
        int R = ByteBuffer.wrap(crypto, 4, 4).getInt();

        L ^= f1(R, K.getKm(15), K.getKr(15));
        R ^= f3(L, K.getKm(14), K.getKr(14));
        L ^= f2(R, K.getKm(13), K.getKr(13));
        R ^= f1(L, K.getKm(12), K.getKr(12));
        L ^= f3(R, K.getKm(11), K.getKr(11));
        R ^= f2(L, K.getKm(10), K.getKr(10));
        L ^= f1(R, K.getKm(9), K.getKr(9));
        R ^= f3(L, K.getKm(8), K.getKr(8));
        L ^= f2(R, K.getKm(7), K.getKr(7));
        R ^= f1(L, K.getKm(6), K.getKr(6));
        L ^= f3(R, K.getKm(5), K.getKr(5));
        R ^= f2(L, K.getKm(4), K.getKr(4));
        L ^= f1(R, K.getKm(3), K.getKr(3));
        R ^= f3(L, K.getKm(2), K.getKr(2));
        L ^= f2(R, K.getKm(1), K.getKr(1));
        R ^= f1(L, K.getKm(0), K.getKr(0));

        unscramble(R, result, 0, 4);
        unscramble(L, result, 4, 8);

        plaintext = result;

    }

    private void unscramble(int x, byte[] array, int start, int stop) {
        byte[] tmp = ByteBuffer.allocate(4).putInt(x).array();
        for (int i = start, j = 0; i < stop; i++, j++)
            array[i] = (byte) (tmp[j] & 0xFF);
    }

    public void printCipherText() {
        System.out.print("CipherText -> ");
        for (int i = 0; i < crypto.length; i++) {
            System.out.print(Integer.toHexString(crypto[i] & 0XFF) + " ");
        }
        System.out.println();
    }

    public void printPlaintext() {
        System.out.print("PlainText -> ");
        for (int i = 0; i < plaintext.length; i++) {
            System.out.print(Integer.toHexString(plaintext[i] & 0XFF) + " ");
        }
        System.out.println();
    }
}