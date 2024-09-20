🚀 Overview

The **RSA Authentication System** is a cutting-edge Java-based application designed for secure user registration and authentication using RSA cryptography. This system ensures the protection of sensitive data with robust RSA public-key encryption and integrates one-time password generators for extra layers of security. The project also provides user-friendly interfaces for seamless client-server communication.

---

## Table of Contents

- [Features](#features)
- [Technologies Used](#technologies-used)
- [Installation](#installation)
- [Usage](#usage)
  - [Running the Server](#running-the-server)
  - [Running the Client](#running-the-client)
  - [Using the Passkey Generators](#using-the-passkey-generators)
- [License](#license)


## 🎯 Features

- **🔑 RSA Public-Key Encryption**: Ensure user credentials and communications are highly secure.
- **📱 One-Time Password Generation**: Adds an extra layer of security to the authentication process.
- **🌐 User-Friendly Interface**: Simplifies the registration and login experience for users.
- **User Registration:** Allows users to register by providing their details and generating RSA key pairs.
- **Secure Authentication:** Utilizes RSA digital signatures to authenticate users securely.
- **Challenge-Response Mechanism:** Implements a challenge-response protocol to verify user identities.
- **Data Persistence:** Stores user credentials and public keys securely on the server.
- **HOTP Code Generators:** Includes tools for generating HOTP (HMAC-Based One-Time Password) strings and hexadecimal passkeys for enhanced security.


---

## Technologies Used

- **Java:** Core programming language for both server and client applications.
- **RSA Cryptography:** For generating key pairs and digital signatures.
- **Swing:** For building the client-side graphical user interface.
- **Networking:** Utilizes Java Sockets for client-server communication.
- **Serialization:** Uses `ObjectInputStream` and `ObjectOutputStream` for data exchange.
- **Security Libraries:** Includes `MessageDigest` and `SecureRandom` for cryptographic operations.

---

## Installation

### Prerequisites

- **Java Development Kit (JDK) 8 or higher** installed on your system.
- **Git** installed for cloning the repository.


1. Clone the repository:
   ```bash
   git clone https://github.com/itsmemdtofik/RSA-Authentication-System.git

5. Compile the Server and Client
  ```bash
javac Server.java
javac ClientAuthnUi.java
javac PasskeyGeneratorHexadecimal.java
javac PasskeyStringGenerator.java
```
---


## License

This project is licensed under the MIT License - see the [LICENSE](./LICENSE) file for details.

Repository link: [https://github.com/itsmemdtofik/RSA-Authentication-System](https://github.com/itsmemdtofik/RSA-Authentication-System)

## Contact

For any inquiries or support, reach out to the project maintainer:

- Name: **Mohammad Tofik**
- GitHub: [itsmemdtofik](https://github.com/itsmemdtofik)
