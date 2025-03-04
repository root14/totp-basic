public class Main {
    /**
     * Example usage
     */
    public static void main(String[] args) {
        // Create TOTP instance with default parameters (6 digits, 30 second period)
        TOTP totp = new TOTP();

        // Generate a new random secret key
        //String secretKey = generateSecretKey(20);
        String secretKey = "JBSWY3DPEHPK3PXP";
        System.out.println("Secret Key: " + secretKey);

        // Generate TOTP code
        String code = totp.generateTOTP(secretKey);
        System.out.println("Current TOTP Code: " + code);

        // Verify TOTP code (should be true if verified immediately)
        boolean isValid = totp.verifyTOTP(secretKey, code);
        System.out.println("Verification result: " + isValid);

        // Display how to use this with Google Authenticator or similar apps
        String otpAuthUrl = "otpauth://totp/Example:user@example.com?secret=" +
                secretKey + "&issuer=Example&algorithm=SHA1&digits=6&period=30";
        System.out.println("OTP Auth URL for Google Authenticator: " + otpAuthUrl);

        // Test with a fixed key for verification
        String testKey = "JBSWY3DPEHPK3PXP"; // Test key
        String testCode = totp.generateTOTP(testKey);
        System.out.println("Test key: " + testKey);
        System.out.println("Generated code: " + testCode);
    }
}
