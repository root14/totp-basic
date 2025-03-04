# TOTP Generator in Java

A standalone Java implementation of the Time-based One-Time Password (TOTP) algorithm, following [RFC 6238](https://tools.ietf.org/html/rfc6238) for TOTP and [RFC 4648](https://tools.ietf.org/html/rfc4648) for Base32 encoding/decoding. This project includes built-in Base32 capabilities and supports multiple HMAC algorithms (SHA1, SHA256, SHA512).

---

## Features

- **TOTP Code Generation:** Generate TOTP codes based on the current time or a specific timestamp.
- **Verification:** Validate TOTP codes with an adjustable time window to account for clock skew.
- **Customizable Parameters:** Configure the HMAC algorithm, number of digits, and time period (default: HMAC-SHA1, 6 digits, 30-second period).
- **Base32 Encoding/Decoding:** Encode and decode Base32 strings as specified in RFC 4648.
- **Secret Key Generation:** Create secure, random secret keys for TOTP authentication.

---

## Getting Started

### Prerequisites

- **Java SE 8** or higher
- A Java IDE or a text editor and terminal for compiling and running Java programs

## Usage

### Generating a TOTP Code

1. **Instantiate the TOTP Class:**
    ```java
    TOTP totp = new TOTP();
    ```

2. **Generate a Secret Key:**
    You can generate a random secret key using:
    ```java
    String secretKey = TOTP.generateSecretKey(20); // 20 bytes for higher security
    ```
    Or use an existing Base32 encoded key:
    ```java
    String secretKey = "JBSWY3DPEHPK3PXP";
    ```

3. **Generate a TOTP Code:**
    ```java
    String code = totp.generateTOTP(secretKey);
    System.out.println("Current TOTP Code: " + code);
    ```

4. **Verify a TOTP Code:**
    ```java
    boolean isValid = totp.verifyTOTP(secretKey, code);
    System.out.println("Verification result: " + isValid);
    ```

### Integration with Authenticator Apps

To integrate with apps like Google Authenticator, construct an OTP Auth URL:
```java
String otpAuthUrl = "otpauth://totp/Example:user@example.com?secret=" +
                    secretKey + "&issuer=Example&algorithm=SHA1&digits=6&period=30";
System.out.println("OTP Auth URL for Google Authenticator: " + otpAuthUrl);
