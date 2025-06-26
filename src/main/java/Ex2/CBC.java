package Ex2;

import java.io.ByteArrayOutputStream;
import java.security.SecureRandom;
import java.util.Arrays;

class CBC {
    private final AES aesCipher;
    private static final int BLOCK_SIZE = 16; // AES的块大小是16字节

    public CBC(byte[] key) {
        this.aesCipher = new AES(key);
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
            byte[] blockToEncrypt = xor(block, previousCipherBlock);
            byte[] cipherBlock = aesCipher.encrypt(blockToEncrypt);
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
        if (ivAndCipherText.length % BLOCK_SIZE != 0 || ivAndCipherText.length == 0) {
            throw new IllegalArgumentException("密文数据无效");
        }

        byte[] iv = Arrays.copyOfRange(ivAndCipherText, 0, BLOCK_SIZE);
        byte[] cipherText = Arrays.copyOfRange(ivAndCipherText, BLOCK_SIZE, ivAndCipherText.length);

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        byte[] previousCipherBlock = iv;

        for (int i = 0; i < cipherText.length; i += BLOCK_SIZE) {
            byte[] block = Arrays.copyOfRange(cipherText, i, i + BLOCK_SIZE);
            byte[] decryptedBlock = aesCipher.decrypt(block);
            byte[] plainTextBlock = xor(decryptedBlock, previousCipherBlock);
            bos.write(plainTextBlock, 0, plainTextBlock.length);
            previousCipherBlock = block;
        }
        return bos.toByteArray();
    }

    private byte[] xor(byte[] a, byte[] b) {
        byte[] result = new byte[a.length];
        for (int i = 0; i < a.length; i++) {
            result[i] = (byte) (a[i] ^ b[i]);
        }
        return result;
    }
}


