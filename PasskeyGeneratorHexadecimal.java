import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class PasskeyGeneratorHexadecimal {
    private static final int RANDOM_PART_LENGTH = 16; // Length of the random part in bytes

    public static void main(String[] args) {
        String userId = "mdtofik@gmail.com";
        try {
            String passkey = generatePasskey(userId);
            System.out.println("Generated Passkey: " + passkey);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public static String generatePasskey(String userId) throws NoSuchAlgorithmException {
        String constantPrefix = generateConstantPrefix(userId);
        SecureRandom secureRandom = new SecureRandom();
        byte[] randomBytes = new byte[RANDOM_PART_LENGTH];
        secureRandom.nextBytes(randomBytes);

        // Convert random bytes to hexadecimal
        String randomPart = bytesToHex(randomBytes);

        // Return the combination of constantPrefix and randomPart
        return constantPrefix + randomPart;
    }

    private static String generateConstantPrefix(String userId) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hashBytes = digest.digest(userId.getBytes());
        return bytesToHex(hashBytes).substring(0, 12); // Adjust length as needed
    }

    // Convert byte array to hexadecimal string
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}

