package Ex1;

public class Main {
    // 测试
    public static void main(String[] args) {
        try {
            // --- DES 测试 ---
            System.out.println("--- DES 测试 ---");
            // byte[] desKey = "12345678".getBytes(); // 8字节密钥
            byte[] desKey = "22345678".getBytes(); // 8字节密钥
            byte[] plainText = "arcdefgh".getBytes(); // 8字节明文

            CBC cbc = new CBC(desKey);
            byte[] desCipherText = cbc.encrypt(plainText);
            byte[] desDecryptedText = cbc.decrypt(desCipherText);

            System.out.println("DES明文: " + new String(plainText));
            System.out.println("DES密文 (Hex): " + bytesToHex(desCipherText));
            System.out.println("DES解密后: " + new String(desDecryptedText));
            System.out.println("验证DES: " + new String(plainText).equals(new String(desDecryptedText)));
            System.out.println();

            // --- 3-DES 测试 ---
            System.out.println("--- 3-DES 测试 ---");
//            byte[] tripleDesKey = "0123456789ABCDEF01234567".getBytes(); // 24字节密钥
            byte[] tripleDesKey = "1123456789ABCDEF01234567".getBytes(); // 24字节密钥

            CBC cbc2 = new CBC(desKey);
            byte[] tripleDesCipherText = cbc2.encrypt(plainText);
            byte[] tripleDesDecryptedText = cbc2.decrypt(desCipherText);

            System.out.println("3-DES明文: " + new String(plainText));
            System.out.println("3-DES密文 (Hex): " + bytesToHex(tripleDesCipherText));
            System.out.println("3-DES解密后: " + new String(tripleDesDecryptedText));
            System.out.println("验证3-DES: " + new String(plainText).equals(new String(tripleDesDecryptedText)));

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // 字节数组转十六进制字符串，方便查看
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }
}
