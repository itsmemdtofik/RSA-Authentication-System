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


import java.lang.reflect.UndeclaredThrowableException;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.util.Scanner;
import java.security.InvalidKeyException;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class HMACBasedOneTimePassword {

    private HMACBasedOneTimePassword() {

    }

    /**
     * These are used to calculate the checksum digits.
     * {0, 1, 2, 3, 4, 5, 6, 7, 8, 9}
     */

    private static final int doubleDigits[] = { 0, 2, 4, 6, 8, 1, 3, 5, 7, 9 };

    /**
     * This algorithm has the advantage that it detects any single
     * mistyped digit and any single transposition of
     * adjacent digits.
     *
     * @param num    the number to calculate the checksum for
     * @param digits number of significant places in the number
     *
     * @return the checksum of num
     */

    private static int calculateCheckSum(long num, int digits) {
        boolean doubleDigit = true;
        int total = 0;
        while (0 < digits--) {
            int digit = (int) (num % 10);
            num = num / 10;

            if (doubleDigit) {
                digit = doubleDigits[digit];
            }
            total = total + digit;
            doubleDigit = !doubleDigit;
        }

        int result = total % 10;
        if (result > 0) {
            result = 10 - result;
        }

        return result;
    }

    /**
     * This method uses the JCE to provide the HMAC-SHA-1
     * 
     * Algorithm
     * HMAC computes a Hashed Message Authentication Code and in this case SHA1 is
     * the hash algorithm used.
     * 
     * @param keyBytes the bytes to use for the HMAC-SHA-1 key the message or text
     *                 to be authenticated.
     * @throws NoSuchAlgorithmException if no provider makes either HmacSHA1 or
     *                                  HMAC-SHA-1 digest algorithms available.
     * @throws InvalidKeyException      The secret provided was not a valid
     *                                  HMAC-SHA-1 key.
     */

    public static byte[] HMACSHA512(byte[] keyBytes, byte[] text) throws NoSuchAlgorithmException, InvalidKeyException {
        try {
            Mac HMAC_SHA_512 = Mac.getInstance("HmacSHA512");
            SecretKeySpec macKey = new SecretKeySpec(keyBytes, "HmacSHA512");
            HMAC_SHA_512.init(macKey);
            return HMAC_SHA_512.doFinal(text);
        } catch (GeneralSecurityException e) {
            throw new UndeclaredThrowableException(e);
        }
    }

    /**
     * 0 1 2 3 4 5 6 7 8
     * 1 10 100 1000 10000 100000 1000000 10000000 100000000
     * 
     */

    private static final int[] digitsPower = { 1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000 };

    /**
     * 
     * This method generate an OTP value for the given set of parameters.
     * 
     * @param secret           the shared secret
     * @param movingFactor     the counter, time, or other value that change per
     *                         user basis.
     * @param codeDigits       the number of digits in the OTP, not including the
     *                         checksum, if any.
     * @param addCheckSum      a flag that indicates if a checksum digit should be
     *                         appended to the OTP.
     * @param truncationOffset the offset into the MAC result to begining
     *                         truncation. If this value is out of the range 0 ...
     *                         15, then dynamic truncation will be used. Dynamic
     *                         truncation is when the last 4 bits of the last byte
     *                         of the MAC are used to determine the start offset.
     * 
     *
     * @throws NoSuchAlgorithmException if no provider makes either HmacSHA1 or
     *                                  HMAC-SHA-1 digest algorithms available.
     * @throws InvalidKeyException      The secret provided was not a valid
     *                                  HMAC-SHA-1 key.
     * @return A numeric String in base 10 that includes
     *         {@link codeDigits} digits plus the optional checksum digit if
     *         requested.
     * 
     * 
     */

    public static String generateOTP(byte[] secret, long movingFactor, int codeDigits, boolean addCheckSum,
            int truncationOffset)
            throws NoSuchAlgorithmException, InvalidKeyException {

        // Convert movingFactor to text byte array
        byte[] text = new byte[8];
        for (int i = text.length - 1; i >= 0; i--) {
            text[i] = (byte) (movingFactor & 0xff);
            movingFactor >>= 8;
        }

        // Compute HMAC-SHA-512 hash
        // byte[] hash = HMACSHA512(secret, text);
        byte[] hash = secret;
        // Determine truncation offset
        int offset = hash[hash.length - 1] & 0xf;
        if (truncationOffset >= 0 && truncationOffset < (hash.length - 4)) {
            offset = truncationOffset;
        }

        // Extract binary value from hash
        int binary = ((hash[offset] & 0x7f) << 24) | ((hash[offset + 1] & 0xff) << 16)
                | ((hash[offset + 2] & 0xff) << 8) | (hash[offset + 3] & 0xff);

        // Compute OTP
        int otp = binary % digitsPower[codeDigits];

        // Add checksum if needed
        if (addCheckSum) {
            int checksum = calculateCheckSum(otp, codeDigits);
            otp = (otp * 10) + checksum; // Ensure checksum does not increase OTP length
        }

        // Ensure OTP length matches the specified codeDigits
        String otpString = Integer.toString(otp);
        if (otpString.length() > codeDigits) {
            otpString = otpString.substring(otpString.length() - codeDigits);
        } else {
            while (otpString.length() < codeDigits) {
                otpString = "0" + otpString;
            }
        }

        System.out.println("+-------------------------------------------+");
        System.out.println("|              Debug Information            |");
        System.out.println("+-------------------------------------------+");
        System.out.println("| Moving Factor Bytes: " + String.format("%-35s", bytesToHex(text)));
        System.out.println("| Truncation Offset: " + String.format("%-35d", offset));

        System.out.println("| Decimal Value: " + String.format("%-37d", binary));
        System.out.println("| OTP Before Checksum: " + String.format("%-27d", otp));
        if (addCheckSum) {
            System.out
                    .println("| Checksum Value: " + String.format("%-29d", calculateCheckSum(otp, codeDigits)));
        }
        System.out.println("+-------------------------------------------+");

        return otpString;
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        boolean running = true;

        while (running) {
            try {
                byte[] secret = new byte[] {
                        (byte) 0x66,
                        (byte) 0xc2,
                        (byte) 0x82,
                        (byte) 0x27,
                        (byte) 0xd0,
                        (byte) 0x3a,
                        (byte) 0x2d,
                        (byte) 0x55,
                        (byte) 0x29,
                        (byte) 0x26,
                        (byte) 0x2f,
                        (byte) 0xf0,
                        (byte) 0x16,
                        (byte) 0xa1,
                        (byte) 0xe6,
                        (byte) 0xef,
                        (byte) 0x76,
                        (byte) 0x55,
                        (byte) 0x7e,
                        (byte) 0xce,
                };

                System.out.print("Enter the moving factor (as a long) : ");
                long movingFactor = Long.parseLong(scanner.nextLine());

                System.out.print("Enter the number of code digits (e.g., 6) : ");
                int codeDigits = Integer.parseInt(scanner.nextLine());

                System.out.print("Add checksum? (true/false) : ");
                boolean addCheckSum = Boolean.parseBoolean(scanner.nextLine());

                System.out.print("Enter the truncation offset (e.g., 0) : ");
                int truncationOffset = Integer.parseInt(scanner.nextLine());

                String otp = HMACBasedOneTimePassword.generateOTP(secret, movingFactor, codeDigits, addCheckSum,
                        truncationOffset);

                System.out.println("+-------------------------------------------+");
                System.out.println("| Generated OTP : " + otp);
                System.out.println("+-------------------------------------------+");

            } catch (NumberFormatException e) {
                System.out.println("Invalid number format. Please try again.");
            } catch (NoSuchAlgorithmException | InvalidKeyException e) {
                System.out.println("Error during OTP generation: " + e.getMessage());
            }

            System.out.println("Do you want to test another OTP? (yes/no):");
            String continueTesting = scanner.nextLine();
            if (!continueTesting.equalsIgnoreCase("yes")) {
                running = false;
                System.out.println("Exiting...");
            }
        }

        scanner.close();
    }

}
