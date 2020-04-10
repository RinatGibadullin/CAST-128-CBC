package cast128;

import javax.xml.bind.DatatypeConverter;
import java.lang.reflect.Array;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;

class Main {

    public static void main(String[] args) throws Exception {
//        Scanner scanner = new Scanner(System.in);
//        System.out.print("Enter your key: ");



        String plain = "0123456789ABCDEF";
        String k = "0123456712345678234567893456789A";
        String init = "0123456789ABCDEF";


        byte[] cipher = CBCEncrypt(plain, k, init);

//        byte[] message = DatatypeConverter.parseHexBinary(plain);
//        byte[] key = DatatypeConverter.parseHexBinary(k);
//        System.out.println("InputText -> " + plain);
//        try {
//            Cast cast = new Cast(key, message);
//            cast.makeKey();
//            cast.encrypt();
//            cast.printCipherText();
//
//            cast.decrypt();
//            cast.printPlaintext();
//        } catch (Exception e) {
//            e.printStackTrace();
//        }

    }


    public static byte[] CBCEncrypt(String m, String k, String init) throws Exception {
        System.out.println("InputText -> " + m);
        byte[] message = DatatypeConverter.parseHexBinary(m);
        byte[] key = DatatypeConverter.parseHexBinary(k);

        long[] p = new long[message.length / 8 + 1];
        long[] c = new long[message.length / 8 + 1];
        c[0] = ByteBuffer.wrap(DatatypeConverter.parseHexBinary(init)).getLong();
        Cast cast = new Cast();
        for (int i = 1; i <= message.length / 8; i++) {
            p[i] = (ByteBuffer.wrap(message, (i - 1) * 8, 8).getLong());
            cast = new Cast(key, ByteBuffer.allocate(8).putLong(p[i] ^ c[i - 1]).array());
            cast.makeKey();
            cast.encrypt();
            c[i] = (ByteBuffer.wrap(cast.getCrypto(), 0, 8).getLong());
        }
        cast.printCipherText();
        System.out.print("PlainText -> ");

        for (int i = 1; i <= message.length / 8; i++) {
            cast.setCrypto(ByteBuffer.allocate(8).putLong(c[i]).array());
            cast.decrypt();
            p[i] = (ByteBuffer.wrap(cast.getPlaintext(), 0, 8).getLong()) ^ c[i-1];

            byte[] result = ByteBuffer.allocate(8).putLong(p[i]).array();
            for (int j = 0; j < result.length; j++) {
                System.out.print(Integer.toHexString(result[j] & 0XFF) + " ");
            }
        }

        return cast.getCrypto();
    }


//    public static byte[] CBCdecrypt(byte[] cipher, String k, String init) throws Exception {
//        byte[] key = DatatypeConverter.parseHexBinary(k);
//
//        long[] p = new long[cipher.length / 8 + 1];
//        long[] c = new long[cipher.length / 8 + 1];
//        c[0] = ByteBuffer.wrap(DatatypeConverter.parseHexBinary(init)).getLong();
//        System.out.println();
//
//
//        Cast cast = new Cast();
//        for (int i = 1; i <= cipher.length / 8; i++) {
//            p[i] = (ByteBuffer.wrap(message, (i - 1) * 8, 8).getLong());
//            cast = new Cast(key, ByteBuffer.allocate(8).putLong(p[i] ^ c[i - 1]).array());
//            cast.makeKey();
//            cast.decrypt();
//            c[i] = (ByteBuffer.wrap(cast.getCrypto(), 0, 8).getLong());
//        }
//        cast.printCipherText();
//    }

}