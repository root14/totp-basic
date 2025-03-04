import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * A standalone Java implementation of TOTP (Time-based One-Time Password)
 * with built-in Base32 encoding/decoding capabilities.
 * Follows RFC 6238 (TOTP) and RFC 4648 (Base32).
 */
public class TOTP {
    // Default parameters
    private static final String DEFAULT_ALGORITHM = "HmacSHA1";
    private static final int DEFAULT_DIGITS = 6;
    private static final int DEFAULT_PERIOD = 30;

    // Base32 alphabet (RFC 4648)
    private static final String BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    private static final char[] BASE32_CHARS = BASE32_ALPHABET.toCharArray();
    private static final byte[] BASE32_LOOKUP = new byte[128];

    static {
        Arrays.fill(BASE32_LOOKUP, (byte) -1);
        for (int i = 0; i < BASE32_CHARS.length; i++) {
            BASE32_LOOKUP[BASE32_CHARS[i]] = (byte) i;
        }
        // Handle lowercase letters as well
        for (int i = 0; i < 26; i++) {
            BASE32_LOOKUP['a' + i] = BASE32_LOOKUP['A' + i];
        }
    }

    // HMAC algorithm to use (SHA1, SHA256, SHA512)
    private final String algorithm;

    // Number of digits in the generated code
    private final int digits;

    // Time step in seconds
    private final int period;

    /**
     * Creates a TOTP generator with default parameters
     */
    public TOTP() {
        this(DEFAULT_ALGORITHM, DEFAULT_DIGITS, DEFAULT_PERIOD);
    }

    /**
     * Creates a TOTP generator with custom parameters
     *
     * @param algorithm HMAC algorithm to use (HmacSHA1, HmacSHA256, HmacSHA512)
     * @param digits    Number of digits in the generated code (usually 6 or 8)
     * @param period    Time step in seconds (usually 30)
     */
    public TOTP(String algorithm, int digits, int period) {
        this.algorithm = algorithm;
        this.digits = digits;
        this.period = period;
    }

    /**
     * Generates a TOTP code for the current time
     *
     * @param secretKey Base32 encoded secret key
     * @return TOTP code
     */
    public String generateTOTP(String secretKey) {
        return generateTOTP(secretKey, System.currentTimeMillis() / 1000);
    }

    /**
     * Generates a TOTP code for a specific time
     *
     * @param secretKey Base32 encoded secret key
     * @param timestamp Unix timestamp in seconds
     * @return TOTP code
     */
    public String generateTOTP(String secretKey, long timestamp) {
        // Convert the timestamp to a counter value based on the period
        long counter = timestamp / period;

        try {
            // Decode the Base32 secret key
            byte[] decodedKey = base32Decode(secretKey);

            // Generate HMAC hash
            byte[] hash = generateHMAC(decodedKey, counter);

            // Dynamic truncation as per RFC 4226
            int offset = hash[hash.length - 1] & 0xF;
            int binary = ((hash[offset] & 0x7F) << 24) |
                    ((hash[offset + 1] & 0xFF) << 16) |
                    ((hash[offset + 2] & 0xFF) << 8) |
                    (hash[offset + 3] & 0xFF);

            // Calculate modulo and convert to string with leading zeros if needed
            int otp = binary % (int) Math.pow(10, digits);
            String result = Integer.toString(otp);

            // Add leading zeros if necessary
            while (result.length() < digits) {
                result = "0" + result;
            }

            return result;

        } catch (Exception e) {
            throw new RuntimeException("Error generating TOTP", e);
        }
    }

    /**
     * Verifies a TOTP code against the current time
     *
     * @param secretKey Base32 encoded secret key
     * @param code      TOTP code to verify
     * @return true if code is valid, false otherwise
     */
    public boolean verifyTOTP(String secretKey, String code) {
        return verifyTOTP(secretKey, code, 1);
    }

    /**
     * Verifies a TOTP code against the current time with a specified window of accepted values
     *
     * @param secretKey  Base32 encoded secret key
     * @param code       TOTP code to verify
     * @param windowSize Number of periods before and after current time to accept
     * @return true if code is valid, false otherwise
     */
    public boolean verifyTOTP(String secretKey, String code, int windowSize) {
        long currentTime = System.currentTimeMillis() / 1000;

        // Check codes for windowSize periods before and after the current time
        for (int i = -windowSize; i <= windowSize; i++) {
            long timestamp = currentTime + (i * period);
            String generatedCode = generateTOTP(secretKey, timestamp);

            if (generatedCode.equals(code)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Generates a random secret key for TOTP
     *
     * @param length Length of the key in bytes (recommended at least 16 bytes for security)
     * @return Base32 encoded secret key
     */
    public static String generateSecretKey(int length) {
        byte[] buffer = new byte[length];
        new SecureRandom().nextBytes(buffer);
        return base32Encode(buffer);
    }

    /**
     * Encodes binary data to Base32 string (RFC 4648)
     *
     * @param data Binary data to encode
     * @return Base32 encoded string
     */
    public static String base32Encode(byte[] data) {
        if (data == null || data.length == 0) {
            return "";
        }

        // Calculate output length
        int outputLength = ((data.length * 8) + 4) / 5;
        StringBuilder result = new StringBuilder(outputLength);

        // Process input data in 5-byte chunks
        int buffer = 0;
        int bitsLeft = 0;

        for (byte b : data) {
            // Add byte to buffer
            buffer = (buffer << 8) | (b & 0xFF);
            bitsLeft += 8;

            // Extract 5-bit chunks
            while (bitsLeft >= 5) {
                bitsLeft -= 5;
                result.append(BASE32_CHARS[(buffer >> bitsLeft) & 0x1F]);
            }
        }

        // Handle remaining bits (if any)
        if (bitsLeft > 0) {
            buffer = buffer << (5 - bitsLeft);
            result.append(BASE32_CHARS[buffer & 0x1F]);
        }

        // Add padding if needed
        while (result.length() % 8 != 0) {
            result.append('=');
        }

        return result.toString();
    }

    /**
     * Decodes a Base32 string to binary data (RFC 4648)
     *
     * @param encoded Base32 encoded string
     * @return Decoded binary data
     * @throws IllegalArgumentException if input contains invalid Base32 characters
     */
    public static byte[] base32Decode(String encoded) {
        if (encoded == null || encoded.isEmpty()) {
            return new byte[0];
        }

        // Remove padding characters and whitespace
        String cleanInput = encoded.trim().toUpperCase().replaceAll("=", "").replaceAll("\\s+", "");

        // Calculate output length
        int outputLength = (cleanInput.length() * 5) / 8;
        byte[] result = new byte[outputLength];

        // Process input in chunks
        int buffer = 0;
        int bitsLeft = 0;
        int resultIndex = 0;

        for (char c : cleanInput.toCharArray()) {
            // Ensure valid Base32 character
            if (c >= BASE32_LOOKUP.length || BASE32_LOOKUP[c] == -1) {
                throw new IllegalArgumentException("Invalid Base32 character: " + c);
            }

            // Add 5 bits to the buffer
            buffer = (buffer << 5) | BASE32_LOOKUP[c];
            bitsLeft += 5;

            // Extract 8-bit bytes
            if (bitsLeft >= 8) {
                bitsLeft -= 8;
                result[resultIndex++] = (byte) ((buffer >> bitsLeft) & 0xFF);
            }
        }

        return result;
    }

    /**
     * Generates an HMAC hash using the specified algorithm
     *
     * @param key     Secret key for HMAC
     * @param counter Counter value
     * @return HMAC hash
     * @throws NoSuchAlgorithmException If the algorithm is not available
     * @throws InvalidKeyException      If the key is invalid
     */
    private byte[] generateHMAC(byte[] key, long counter)
            throws NoSuchAlgorithmException, InvalidKeyException {
        // Convert counter to 8-byte big-endian buffer
        byte[] buffer = ByteBuffer.allocate(8).putLong(0, counter).array();

        // Create HMAC instance with specified algorithm
        Mac mac = Mac.getInstance(algorithm);
        mac.init(new SecretKeySpec(key, algorithm));

        // Compute HMAC
        return mac.doFinal(buffer);
    }
}