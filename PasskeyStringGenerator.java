
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
