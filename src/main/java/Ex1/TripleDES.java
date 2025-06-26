package Ex1;

import java.util.Arrays;

/**
 * 3-DES (三重DES) 实现
 * - 使用 EDE (Encrypt-Decrypt-Encrypt) 模式
 * - 需要一个24字节 (192位) 的密钥，分成3个8字节的DES密钥 (K1, K2, K3)
 */
public class TripleDES {

    private DES des1;
    private DES des2;
    private DES des3;

    public TripleDES(byte[] key) {
        if (key == null || key.length != 24) {
            throw new IllegalArgumentException("3-DES密钥长度必须是24字节 (192位)");
        }
        // 将24字节密钥分成3个8字节的密钥
        byte[] key1 = Arrays.copyOfRange(key, 0, 8);
        byte[] key2 = Arrays.copyOfRange(key, 8, 16);
        byte[] key3 = Arrays.copyOfRange(key, 16, 24);

        // 创建3个DES实例
        this.des1 = new DES(key1);
        this.des2 = new DES(key2);
        // 为了兼容性，有时K3=K1，但这里我们使用3个独立密钥
        this.des3 = new DES(key3);
    }

    public byte[] encrypt(byte[] plainText) {
        // 第一轮：使用K1加密
        byte[] afterDes1 = des1.encrypt(plainText);
        // 第二轮：使用K2解密
        byte[] afterDes2 = des2.decrypt(afterDes1);
        // 第三轮：使用K3加密
        return des3.encrypt(afterDes2);
    }

    public byte[] decrypt(byte[] cipherText) {
        // 第一轮：使用K3解密
        byte[] afterDes3 = des3.decrypt(cipherText);
        // 第二轮：使用K2加密
        byte[] afterDes2 = des2.encrypt(afterDes3);
        // 第三轮：使用K1解密
        return des1.decrypt(afterDes2);
    }
}