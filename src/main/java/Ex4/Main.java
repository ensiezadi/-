package Ex4;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Main {
    public static void main(String[] args) throws IOException, NoSuchAlgorithmException {

        System.out.println("--- SHA-256 Test ---");
        String str = "ch-happz";

        String myResult = sha2.encrypt(str);

        // 使用 Java 自带的 MessageDigest 标准库进行对比验证
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] encodedhash = digest.digest(str.getBytes(StandardCharsets.UTF_8));
        String jceResult = bytesToHex(encodedhash);

        System.out.println("My SHA-256    : " + myResult);
        System.out.println("JCE SHA-256   : " + jceResult);
        System.out.println("Is Correct    : " + myResult.equals(jceResult));
        System.out.println();

        String message1 = "abc";
        String expectedHash = "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0";
        String actualHash = sm3.sm3Hash(message1);
        System.out.println("--- Standard SM3 Hash Test ---");
        System.out.println("Message: \"" + message1 + "\"");
        System.out.println("Expected Hash: " + expectedHash);
        System.out.println("Actual Hash  : " + actualHash);
        System.out.println("Is Correct   : " + expectedHash.equals(actualHash));
        System.out.println();
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
