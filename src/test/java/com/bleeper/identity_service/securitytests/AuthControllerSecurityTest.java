package com.bleeper.identity_service.securitytests;

import com.bleeper.identity_service.controllers.AuthController;
import com.bleeper.identity_service.payload.LoginRequest;
import com.bleeper.identity_service.repositories.UserRepository;
import com.bleeper.identity_service.security.TokenProvider;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectWriter;
import io.jsonwebtoken.security.Password;
import jakarta.servlet.Filter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.ImportAutoConfiguration;
import org.springframework.boot.autoconfigure.security.oauth2.client.servlet.OAuth2ClientAutoConfiguration;
import org.springframework.boot.autoconfigure.security.oauth2.resource.servlet.OAuth2ResourceServerAutoConfiguration;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
//@SpringBootTest(classes = {
//        AuthController.class,
//        AuthControllerSecurityTest.TestConfig.class
//})
@AutoConfigureMockMvc(addFilters = true)
@ImportAutoConfiguration(exclude = {OAuth2ClientAutoConfiguration.class, OAuth2ResourceServerAutoConfiguration.class})
//@TestPropertySource(properties = "spring.main.allow-bean-definition-overriding=true")
class AuthControllerSecurityTest {

    @Autowired private MockMvc mockMvc;
    ObjectWriter ow = new ObjectMapper().writer().withDefaultPrettyPrinter();

    @Autowired private AuthenticationManager authManager;
    @Autowired private TokenProvider tokenProvider;
    @Autowired private UserRepository userRepository; // Mock the missing repo


    @Configuration
    static class TestConfig {
        @Bean
        AuthenticationManager authManager() {
            return Mockito.mock(AuthenticationManager.class);
        }

        @Bean
        TokenProvider tokenProvider() {
            return Mockito.mock(TokenProvider.class);
        }

        @Bean
        public UserRepository userRepository() {
            return Mockito.mock(UserRepository.class);
        }

        @Bean
        public PasswordEncoder passwordEncoder() {
            return Mockito.mock(PasswordEncoder.class);
        }

        @Bean
        public AuthController authController(
                AuthenticationManager authManager,
                TokenProvider tokenProvider,
                UserRepository userRepository,
                PasswordEncoder passwordEncoder
        ) {
            return new AuthController(authManager, tokenProvider, userRepository, passwordEncoder);
        }

        // If security filter is global, import it here or disable
        // @Bean public Filter springSecurityFilterChain(...) { ... }
    }

    @BeforeEach
    void resetMocks() {
        Mockito.reset(authManager, tokenProvider);
    }

    @Test
    void loginWithValidCredentials_returnsToken() throws Exception {
        var req = new LoginRequest("user", "pass");
        var auth = mock(Authentication.class);
        when(authManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenReturn(auth);
        when(tokenProvider.createToken(auth))
                .thenReturn("mocked-token");

        mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .characterEncoding("utf-8")
                        .content(ow.writeValueAsString(req))
                        .with(csrf()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token").value("mocked-token"));
    }

    @Test
    void loginWithInvalidCredentials_returns401() throws Exception {
        var req = new LoginRequest("bad", "cred");
        when(authManager.authenticate(any()))
                .thenThrow(new BadCredentialsException("Bad creds"));

        mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .characterEncoding("utf-8")
                        .content(ow.writeValueAsString(req))
                        .with(csrf()))
                .andExpect(status().isUnauthorized());
    }
}
