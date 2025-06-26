package Ex1;

import java.io.ByteArrayOutputStream;
import java.security.SecureRandom;
import java.util.Arrays;

public class CBC {
    private DES desCipher;
    private TripleDES tripleDES;
    private final boolean isTripleDES; // 标记当前使用的是否为3-DES

    private static final int BLOCK_SIZE = 8;

    /**
     * 构造函数。根据密钥长度自动选择DES或3-DES。
     * @param key 用于加密的密钥。DES为8字节，3-DES为24字节。
     */
    public CBC(byte[] key) {
        if (key.length == 24) {
            this.tripleDES = new TripleDES(key);
            this.isTripleDES = true;
            this.desCipher = null;
        } else if (key.length == 8) {
            this.desCipher = new DES(key);
            this.isTripleDES = false;
            this.tripleDES = null;
        } else {
            throw new IllegalArgumentException("密钥长度无效：DES需要8字节，3-DES需要24字节");
        }
    }

    public byte[] encrypt(byte[] plainText) {
        if (plainText.length % BLOCK_SIZE != 0) {
            throw new IllegalArgumentException("错误：明文长度必须是 " + BLOCK_SIZE + " 字节的整数倍");
        }

        SecureRandom random = new SecureRandom();
        byte[] iv = new byte[BLOCK_SIZE];
        random.nextBytes(iv);

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        byte[] previousCipherBlock = iv;

        for (int i = 0; i < plainText.length; i += BLOCK_SIZE) {
            byte[] block = Arrays.copyOfRange(plainText, i, i + BLOCK_SIZE);

            for (int j = 0; j < BLOCK_SIZE; j++) {
                block[j] = (byte) (block[j] ^ previousCipherBlock[j]);
            }

            byte[] cipherBlock;
            // 根据构造时确定的类型选择加密器
            cipherBlock = isTripleDES ? tripleDES.encrypt(block) : desCipher.encrypt(block);

            bos.write(cipherBlock, 0, cipherBlock.length);
            previousCipherBlock = cipherBlock;
        }

        byte[] cipherText = bos.toByteArray();

        byte[] result = new byte[iv.length + cipherText.length];
        System.arraycopy(iv, 0, result, 0, iv.length);
        System.arraycopy(cipherText, 0, result, iv.length, cipherText.length);
        return result;
    }

    public byte[] decrypt(byte[] ivAndCipherText) {
        if (ivAndCipherText == null || ivAndCipherText.length < BLOCK_SIZE * 2) {
            throw new IllegalArgumentException("密文数据无效：长度过短");
        }

        byte[] iv = Arrays.copyOfRange(ivAndCipherText, 0, BLOCK_SIZE);
        byte[] cipherText = Arrays.copyOfRange(ivAndCipherText, BLOCK_SIZE, ivAndCipherText.length);

        if (cipherText.length % BLOCK_SIZE != 0) {
            throw new IllegalArgumentException("密文长度必须是块大小的整数倍");
        }

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        byte[] previousCipherBlock = iv;

        for (int i = 0; i < cipherText.length; i += BLOCK_SIZE) {
            byte[] block = Arrays.copyOfRange(cipherText, i, i + BLOCK_SIZE);

            byte[] decryptedBlock;
            // 根据构造时确定的类型选择解密器
            decryptedBlock = isTripleDES ? tripleDES.decrypt(block) : desCipher.decrypt(block);


            byte[] plainTextBlock = xor(decryptedBlock, previousCipherBlock);
            bos.write(plainTextBlock, 0, plainTextBlock.length);
            previousCipherBlock = block;
        }

        return bos.toByteArray();
    }

    private byte[] xor(byte[] a, byte[] b) {
        byte[] result = new byte[a.length];
        for (int i = 0; i < a.length; i++) {
            result[i] = (byte)(a[i] ^ b[i]);
        }
        return result;
    }
}
