package com.bleeper.identity_service.payload;

import lombok.Data;

@Data
public class AuthResponse {
    private final String accessToken;
    private String tokenType = "Bearer";
}
