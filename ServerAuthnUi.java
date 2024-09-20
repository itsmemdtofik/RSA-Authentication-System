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


import java.io.*;
import java.net.*;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;
import java.util.HashMap;
import javax.crypto.Cipher;

public class ServerAuthnUi {

    /**
     * Convert PEM format back to private key
     * 
     * @param privateKeyPem
     * @return
     * @throws Exception
     */
    public static PrivateKey deserializePrivateKey(String privateKeyPem) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(privateKeyPem);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(spec);
    }

    /**
     * Convert PEM format back to public key
     * 
     * @param publicKeyPem
     * @return
     * @throws Exception
     */
    public static PublicKey deserializePublicKey(String publicKeyPem) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(publicKeyPem);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(spec);
    }

    /**
     * Verify the signature with the public key
     * 
     * @param publicKey
     * @param challenge
     * @param signature
     * @return
     * @throws Exception
     */
    public static boolean verifySignature(PublicKey publicKey, byte[] challenge, byte[] signature) throws Exception {
        Signature publicSignature = Signature.getInstance("SHA512withRSA");
        publicSignature.initVerify(publicKey);
        publicSignature.update(challenge);
        return publicSignature.verify(signature);
    }

    /**
     * Decrypt the signature to retrieve the challenge
     * 
     * @param publicKey
     * @param signature
     * @return
     * @throws Exception
     */
    public static byte[] decryptSignature(PublicKey publicKey, byte[] signature) throws Exception {
        if (signature == null) {
            throw new IllegalArgumentException("Null input buffer");
        }
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, publicKey);
        return cipher.doFinal(signature);
    }

    /**
     * Start the server
     * 
     * @param host
     * @param port
     * @throws Exception
     */
    public static void startServer(String host, int port) throws Exception {
        @SuppressWarnings("resource")
        ServerSocket serverSocket = new ServerSocket(port);
        System.out.println("Server listening on " + host + ":" + port);

        while (true) {
            Socket clientSocket = serverSocket.accept();
            System.out.println("Connection from " + clientSocket.getInetAddress());

            ObjectInputStream in = new ObjectInputStream(clientSocket.getInputStream());
            ObjectOutputStream out = new ObjectOutputStream(clientSocket.getOutputStream());

            @SuppressWarnings("unchecked")
            HashMap<String, Object> request = (HashMap<String, Object>) in.readObject();
            HashMap<String, Object> response = new HashMap<>();

            String requestType = (String) request.get("type");
            String username = (String) request.get("username");

            if (username == null || username.isEmpty()) {
                response.put("response", "Username is required.");
                System.out.println("Username is required.");
            } else if (requestType.equals("register")) {
                String publicKeyPem = (String) request.get("public_key");
                byte[] challenge = new byte[32];
                new SecureRandom().nextBytes(challenge);
                try (FileOutputStream fos = new FileOutputStream(username + "_public_key.pem")) {
                    fos.write(Base64.getDecoder().decode(publicKeyPem));
                }
                response.put("message", "Registration successful.");
                response.put("challenge", challenge);
                System.out.println("\nRegistration: Public key stored and challenge sent for user: " + username);
                System.out.println(
                        "Server Challenge (Registration): " + Base64.getEncoder().encodeToString(challenge) + "\n");

            } else if (requestType.equals("authenticate")) {
                byte[] challenge = new byte[32];
                new SecureRandom().nextBytes(challenge);
                response.put("challenge", challenge);
                System.out.println(
                        "Server Challenge (Authentication): " + Base64.getEncoder().encodeToString(challenge) + "\n");

            } else if (requestType.equals("verify")) {
                String publicKeyPem = (String) request.get("public_key");
                byte[] challenge = (byte[]) request.get("challenge");
                byte[] signature = (byte[]) request.get("signature");

                PublicKey publicKey = deserializePublicKey(publicKeyPem);
                boolean isValid = verifySignature(publicKey, challenge, signature);

                System.out.println(
                        "Received Challenge (Verify): " + Base64.getEncoder().encodeToString(challenge) + "\n");
                System.out.println("Signature (Verify): " + Base64.getEncoder().encodeToString(signature) + "\n");

                // Decrypt the signature to get the original challenge
                byte[] decryptedChallenge = decryptSignature(publicKey, signature);
                System.out.println("Decrypted Challenge (Verify): "
                        + Base64.getEncoder().encodeToString(decryptedChallenge) + "\n");

                if (isValid) {
                    response.put("response", "Authentication successful.");
                    System.out.println("Authentication successful.");
                } else {
                    response.put("response", "Authentication failed.");
                    System.out.println("Authentication failed.\n");
                }
            }

            out.writeObject(response);
            clientSocket.close();
        }
    }

    public static void main(String[] args) throws Exception {
        startServer("localhost", 65432);
    }
}
