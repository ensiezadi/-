package Ex2;

import java.util.Base64;

public class Main {

    public static void main(String[] args) {
        try {
            // 1. 准备密钥和明文
            // 密钥必须是16字节 (128位)
            byte[] key = "ny-secret-key-16".getBytes();
            // 明文长度必须是16字节的倍数
            String originalText = "This is a secret";
            byte[] plainText = originalText.getBytes("UTF-8");

            System.out.println("原始密钥 (Hex): " + new String(key, "UTF-8"));
            System.out.println("原始明文: " + originalText);
//            System.out.println("明文长度: " + plainText.length + " 字节");

            // 2. 创建CBC模式的AES加密器
            CBC cbc = new CBC(key);

            // 3. 加密
            byte[] encryptedData = cbc.encrypt(plainText);

            // 4. 解密
            byte[] decryptedData = cbc.decrypt(encryptedData);

            // 5. 验证结果
            String decryptedText = new String(decryptedData, "UTF-8");

            System.out.println("加密后 (Base64): " + Base64.getEncoder().encodeToString(encryptedData));
//            System.out.println("加密后 (Hex): " + bytesToHex(encryptedData));
            System.out.println("解密后明文: " + decryptedText);
            System.out.println("验证是否成功: " + originalText.equals(decryptedText));

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // 辅助函数: 字节数组转十六进制字符串
//    public static String bytesToHex(byte[] bytes) {
//        StringBuilder sb = new StringBuilder();
//        for (byte b : bytes) {
//            sb.append(String.format("%02X ", b));
//        }
//        return sb.toString().trim();
//    }
}
