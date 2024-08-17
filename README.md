# SecureFile - Advanced File Encryption Utility

![SecureFile Logo](assets/securefile_logo.png)

SecureFile is a robust, military-grade file encryption tool built for the Kali Linux environment. Designed with security in mind, SecureFile ensures that your sensitive data remains protected from unauthorized access. This utility leverages advanced cryptographic algorithms and modern security practices to provide unparalleled file encryption and decryption capabilities.

## Features

- **Strong Encryption**: Utilizes AES-GCM with Argon2 for key derivation, ensuring high security.
- **File Integrity Checks**: Incorporates HMAC to verify file integrity during encryption and decryption.
- **Cross-Format Support**: Works with any file format, from text files to images and executables.
- **Metadata Protection**: Encrypts file metadata to prevent leakage of sensitive information.
- **Error Handling**: Provides clear error messages for incorrect inputs and potential security issues.
- **File Deletion**: Securely deletes original files after encryption/decryption, minimizing the risk of data leakage.
- **Kali Linux Integration**: Seamlessly integrates with the Kali Linux environment for easy deployment.

## Table of Contents

- [Installation](#installation)
- [Usage](#usage)
  - [Encrypting Files](#encrypting-files)
  - [Decrypting Files](#decrypting-files)
- [Advanced Security Features](#advanced-security-features)
- [Contributing](#contributing)
- [License](#license)

## Installation

### Prerequisites

Before installing SecureFile, ensure you have the following dependencies installed:

- Python 3.10 or later
- `pip` (Python package installer)
- Kali Linux (or compatible Linux environment)

### Basic Setup

Follow these steps to clone the project, configure it, and start using SecureFile.

1. **Clone the repository:**

   ```bash
   git clone https://github.com/brianparkerin/asscrypt.git
   cd securefile
