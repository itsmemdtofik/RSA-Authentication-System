/*
 * MIT License
 * 
 * Copyright (c) 2024 Mohammad Tofik
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */


import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class PasskeyStringGenerator {
    private static final int RANDOM_PART_LENGTH = 16; // Length of the random part in bytes

    public static String generatePasskey(String userId) throws NoSuchAlgorithmException {
        String constantPrefix = generateConstantPrefix(userId);
        SecureRandom secureRandom = new SecureRandom();
        byte[] randomBytes = new byte[RANDOM_PART_LENGTH];
        secureRandom.nextBytes(randomBytes);

        // Convert random bytes to a string containing only alphabetic characters
        String randomPart = bytesToAlphabetic(randomBytes);

        // Return the combination of constantPrefix and randomPart
        return constantPrefix + randomPart;
    }

    private static String generateConstantPrefix(String userId) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hashBytes = digest.digest(userId.getBytes());
        return bytesToAlphabetic(hashBytes).substring(0, 12); // Adjust length as needed
    }

    // Convert byte array to a string containing only alphabetic characters
    private static String bytesToAlphabetic(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            // Convert each byte to an alphabetic character
            // We use a base 26 encoding (letters only)
            sb.append((char) ('a' + (b & 0x0F))); // Limiting to a subset of letters
        }
        return sb.toString();
    }

    public static void main(String[] args) {
        String userId = "itsmemdtofik@gmail.com";
        try {
            String passkey = generatePasskey(userId);
            System.out.println("Generated Passkey: " + passkey);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }
}
