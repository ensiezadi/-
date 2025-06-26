package Ex3;

import java.math.BigInteger;

public class Main {

    public static void main(String[] args) {
        // Initialize RSA and Util classes
        RSA rsa = new RSA();
        Util util = new Util();

        // Generate public and private keys
        myPQ publicKey = rsa.getPublicKey();
        myPQ privateKey = rsa.getPrivateKey(publicKey);

        System.out.println("Public Key: " + publicKey.getP() + ", " + publicKey.getQ());
        System.out.println("Private Key: " + privateKey.getP() + ", " + privateKey.getQ());

        // Test encryption and decryption of a number
        BigInteger testNumber = new BigInteger("223456789");
        BigInteger encryptedNumber = rsa.encode(testNumber, publicKey);
        BigInteger decryptedNumber = rsa.decode(encryptedNumber, privateKey);

        System.out.println("Original Number: " + testNumber);
        System.out.println("Encrypted Number: " + encryptedNumber);
        System.out.println("Decrypted Number: " + decryptedNumber);

        // Test encryption and decryption of a string
        // String testString = "Hello, RSA Encryption!";
        String testString = "Hello, YXL";
        String encodedFilePath = "src/main/resources/encoded.txt";

        rsa.encode(testString, publicKey, encodedFilePath);
        String decodedString = rsa.decode(encodedFilePath, privateKey);

        System.out.println("Original String: " + testString);
        System.out.println("Decoded String: " + decodedString);
    }
}
