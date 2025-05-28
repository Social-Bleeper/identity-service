package com.bleeper.identity_service.controllers;

import com.bleeper.identity_service.security.TokenProvider;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RequiredArgsConstructor
@RestController
@RequestMapping("/.well-known")
public class JwksController {

    private final TokenProvider tokenProvider;

    @GetMapping("/jwks.json")
    public ResponseEntity<String> getJwks() throws Exception {
        RSAKey jwk = new RSAKey.Builder((java.security.interfaces.RSAPublicKey) tokenProvider.loadPublicKey())
                .keyID("my-key-id") // Unique key ID
                .build();

        return ResponseEntity
                .ok(new JWKSet(jwk).toJSONObject().toString());
    }
}
