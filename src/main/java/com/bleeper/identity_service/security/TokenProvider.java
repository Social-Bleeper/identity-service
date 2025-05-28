package com.bleeper.identity_service.security;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.SignatureException;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

import java.io.InputStream;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Date;
import java.util.UUID;

@RequiredArgsConstructor
@Service
public class TokenProvider {

    private static final Logger logger = LoggerFactory.getLogger(TokenProvider.class);

    private final PrivateKey privateKey;
    private final PublicKey publicKey;

    public TokenProvider() throws Exception {
        this.privateKey = loadPrivateKey(); // Load from file
        this.publicKey = loadPublicKey();
    }

    public String createToken(Authentication authentication) {
        UserPrincipal userPrincipal = (UserPrincipal) authentication.getPrincipal();

        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + 360000); // 1-hour expiry

        return Jwts.builder()
                .issuer("http://identity:8081/")
                .subject(userPrincipal.getPublicId().toString())
                .expiration(expiryDate)
                .issuedAt(new Date())
                .signWith(privateKey)
                .compact();
    }

    public Long extractPublicUserId(String token) {
        return Long.parseLong(extractClaims(token).getSubject());
    }

    public boolean validateToken(String token) {
        try {
            extractClaims(token);
            return true;
        } catch (SignatureException ex) {
            logger.error("Invalid JWT signature");
        } catch (MalformedJwtException ex) {
            logger.error("Invalid JWT token");
        } catch (ExpiredJwtException ex) {
            logger.error("Expired JWT token");
        } catch (UnsupportedJwtException ex) {
            logger.error("Unsupported JWT token");
        } catch (IllegalArgumentException ex) {
            logger.error("JWT claims string is empty.");
        }
        return false;
    }

    private PrivateKey loadPrivateKey() throws Exception {
        InputStream inputStream = new ClassPathResource("private_pkcs8.pem").getInputStream();
        byte[] keyBytes = inputStream.readAllBytes();
        // Remove header/footer if present (PEM format)
        String keyString = new String(keyBytes)
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", ""); // Remove new lines and spaces

        byte[] decodedKey = Base64.getDecoder().decode(keyString);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decodedKey);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(keySpec);
    }

    public PublicKey loadPublicKey() throws Exception {
        InputStream inputStream = new ClassPathResource("public.pem").getInputStream();
        byte[] keyBytes = inputStream.readAllBytes();
        // Remove header/footer if present (PEM format)
        String keyString = new String(keyBytes)
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", ""); // Remove new lines and spaces

        byte[] decodedKey = Base64.getDecoder().decode(keyString);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decodedKey);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(keySpec);
    }

    private Claims extractClaims(String token) {
        return Jwts.parser()
                .verifyWith(publicKey) // Verify the token with the correct key
                .build()
                .parseSignedClaims(token) // Parse token and extract claims
                .getPayload();
    }
}
