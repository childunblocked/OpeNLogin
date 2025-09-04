package com.nickuc.openlogin.common.security.hashing;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public final class Sha256 {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final int SALT_LENGTH = 16; // 16 hex characters (8 bytes)

    /** Generate a random hex salt */
    public static String generateSalt() {
        byte[] saltBytes = new byte[SALT_LENGTH / 2]; // 8 bytes
        RANDOM.nextBytes(saltBytes);
        return bytesToHex(saltBytes);
    }

    /** Convert bytes to hex string */
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b & 0xff));
        }
        return sb.toString();
    }

    /** Compute SHA-256 hash */
    private static String sha256(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(input.getBytes(StandardCharsets.UTF_8));
            return bytesToHex(hashBytes);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }

    /** Compute AuthMe-style hash: $SHA$<salt>$<doubleSHA> */
    public static String generate(String password) {
        String salt = generateSalt();
        return "$SHA$" + salt + "$" + computeHash(password, salt);
    }

    /** Compute hash from password and salt */
    public static String computeHash(String password, String salt) {
        return sha256(sha256(password) + salt);
    }

    /** Verify password against stored AuthMe hash */
    public static boolean verify(String password, String stored) {
        if (stored == null || !stored.startsWith("$SHA$")) return false;
        String[] parts = stored.split("\\$");
        if (parts.length != 4) return false;
        String salt = parts[2];
        String hash = parts[3];
        return computeHash(password, salt).equalsIgnoreCase(hash);
    }
}
