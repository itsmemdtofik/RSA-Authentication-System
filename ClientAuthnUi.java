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
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Scanner;
import javax.crypto.Cipher;
import javax.swing.*;

public class ClientAuthnUi {

    private static final SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

    /**
     * Generaing key pairs.
     * 
     * @return
     * @throws NoSuchAlgorithmException
     */
    public static KeyPair generateKeys() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        return keyGen.generateKeyPair();
    }

    /**
     * Serializing the private key.
     * 
     * @param privateKey
     * @return
     */
    public static String serializePrivateKey(PrivateKey privateKey) {
        return Base64.getEncoder().encodeToString(privateKey.getEncoded());
    }

    /**
     * Seriliazing the public key.
     * 
     * @param publicKey
     * @return
     */
    public static String serializePublicKey(PublicKey publicKey) {
        return Base64.getEncoder().encodeToString(publicKey.getEncoded());
    }

    /**
     * Signing the challenge with the private key.
     * 
     * @param privateKey
     * @param challenge
     * @return
     * @throws Exception
     */
    public static byte[] signChallenge(PrivateKey privateKey, byte[] challenge) throws Exception {
        Signature privateSignature = Signature.getInstance("SHA512withRSA");
        privateSignature.initSign(privateKey);
        privateSignature.update(challenge);
        return privateSignature.sign();
    }

    /**
     * Date sent to server
     * 
     * @param data
     * @param host
     * @param port
     * @return
     * @throws Exception
     */
    @SuppressWarnings("unchecked")
    public static HashMap<String, Object> sendToServer(HashMap<String, Object> data, String host, int port)
            throws Exception {
        Socket clientSocket = new Socket(host, port);
        ObjectOutputStream out = new ObjectOutputStream(clientSocket.getOutputStream());
        ObjectInputStream in = new ObjectInputStream(clientSocket.getInputStream());
        out.writeObject(data);
        HashMap<String, Object> response = (HashMap<String, Object>) in.readObject();
        clientSocket.close();
        return response;
    }

    /**
     * User Registration
     * 
     * @throws Exception
     */
    public static void registration() throws Exception {
        JTextField firstNameField = new JTextField();
        JTextField lastNameField = new JTextField();
        JTextField usernameField = new JTextField();
        JPasswordField passwordField = new JPasswordField();

        Object[] fields = {
                "First Name:", firstNameField,
                "Last Name:", lastNameField,
                "Username (Gmail or Mobile):", usernameField,
                "Password:", passwordField
        };

        int option = JOptionPane.showConfirmDialog(null, fields, "User Registration", JOptionPane.OK_CANCEL_OPTION);
        if (option == JOptionPane.OK_OPTION) {
            String firstName = firstNameField.getText();
            String lastName = lastNameField.getText();
            String username = usernameField.getText();
            String password = new String(passwordField.getPassword());
            String registrationDate = dateFormat.format(new Date());

            if (!username.matches("^[\\w._%+-]+@[\\w.-]+\\.[a-zA-Z]{2,}$") && !username.matches("^\\+?[0-9]{10,13}$")) {
                JOptionPane.showMessageDialog(null,
                        "Invalid username. Please enter a valid Gmail ID or mobile number.");
                registration();
                return;
            }

            KeyPair keyPair = generateKeys();
            PrivateKey privateKey = keyPair.getPrivate();
            PublicKey publicKey = keyPair.getPublic();

            System.out.println("Registration:\n");
            System.out.println("Private Key:\n" + serializePrivateKey(privateKey) + "\n");
            System.out.println("Public Key:\n" + serializePublicKey(publicKey) + "\n");

            HashMap<String, Object> data = new HashMap<>();
            data.put("type", "register");
            data.put("first_name", firstName);
            data.put("last_name", lastName);
            data.put("username", username);
            data.put("password", password);
            data.put("registration_date", registrationDate);
            data.put("public_key", serializePublicKey(publicKey));

            HashMap<String, Object> response = sendToServer(data, "localhost", 65432);
            byte[] challenge = (byte[]) response.get("challenge");
            System.out.println(
                    "Server Challenge (Registration): " + Base64.getEncoder().encodeToString(challenge) + "\n");

            byte[] signature = signChallenge(privateKey, challenge);
            System.out.println("Signature (Registration, signed with private key): "
                    + Base64.getEncoder().encodeToString(signature) + "\n");

            try (BufferedWriter writer = new BufferedWriter(new FileWriter("data.txt", true))) {
                writer.write(username + "," + password + "," + registrationDate + "," +
                        serializePrivateKey(privateKey) + "," + serializePublicKey(publicKey) + "\n");
            }
        }
    }

    /**
     * Decrypting the signature using private key.
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
     * User and server Authentication
     * 
     * @throws Exception
     */
    public static void authentication() throws Exception {
        String username = JOptionPane.showInputDialog("Enter your username (Gmail or Mobile):");
        JPasswordField passwordField = new JPasswordField();
        int option = JOptionPane.showConfirmDialog(null, new Object[] { "Password:", passwordField }, "Authentication",
                JOptionPane.OK_CANCEL_OPTION);
        if (option == JOptionPane.OK_OPTION) {
            String password = new String(passwordField.getPassword());

            byte[] challenge = null;
            byte[] signature = null;
            PrivateKey privateKey = null;
            PublicKey publicKey = null;
            @SuppressWarnings("unused")
            String registrationDate = null;
            boolean authenticated = false;

            try (Scanner scanner = new Scanner(new File("data.txt"))) {
                while (scanner.hasNextLine()) {
                    String line = scanner.nextLine();
                    String[] parts = line.split(",");
                    if (parts[0].equals(username) && parts[1].equals(password)) {
                        registrationDate = parts[2];
                        privateKey = deserializePrivateKey(parts[3]);
                        publicKey = deserializePublicKey(parts[4]);
                        authenticated = true;
                        break;
                    }
                }
            }

            if (!authenticated) {
                JOptionPane.showMessageDialog(null, "Invalid username or password. Please register.");
                registration();
                return;
            }

            HashMap<String, Object> data = new HashMap<>();
            data.put("type", "authenticate");
            data.put("username", username);
            data.put("password", password);
            data.put("public_key", serializePublicKey(publicKey));

            HashMap<String, Object> response = sendToServer(data, "localhost", 65432);
            challenge = (byte[]) response.get("challenge");
            System.out.println(
                    "Server Challenge (Authentication): " + Base64.getEncoder().encodeToString(challenge) + "\n");

            signature = signChallenge(privateKey, challenge);
            System.out.println("Signature (Authentication, signed with private key): "
                    + Base64.getEncoder().encodeToString(signature) + "\n");

            byte[] decryptedChallenge = decryptSignature(publicKey, signature);
            System.out.println("Decrypted Challenge (Verify): "
                    + Base64.getEncoder().encodeToString(decryptedChallenge) + "\n");

            data = new HashMap<>();
            data.put("type", "verify");
            data.put("username", username);
            data.put("public_key", serializePublicKey(publicKey));
            data.put("challenge", challenge);
            data.put("signature", signature);

            response = sendToServer(data, "localhost", 65432);
            System.out.println("Server response: " + response.get("response") + "\n");

            if ("Authentication successful.".equals(response.get("response"))) {
                System.out.println("Authentication successful.");
            } else {
                System.out.println("Authentication failed. Please register again.");
                registration();
            }
        }
    }

    /**
     * Deserializeing the private key
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
     * Deserializing the public key.
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

    public static void main(String[] args) throws Exception {
        File file = new File("data.txt");
        if (!file.exists() || file.length() == 0) {
            registration();
        } else {
            authentication();
        }
    }
}
