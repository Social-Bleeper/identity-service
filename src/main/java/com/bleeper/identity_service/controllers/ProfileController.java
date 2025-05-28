package com.bleeper.identity_service.controllers;

import com.bleeper.identity_service.models.Profile;
import com.bleeper.identity_service.models.User;
import com.bleeper.identity_service.repositories.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Optional;

@RestController
@RequestMapping("/profile")
@RequiredArgsConstructor
public class ProfileController {
    private final UserRepository userRepository;

    @GetMapping
    public ResponseEntity<Profile> getUserProfile(@AuthenticationPrincipal Jwt jwt) {
        String subject = jwt.getSubject();
        Optional<User> userOptional = userRepository.findById(Long.parseLong(subject));


        if (userOptional.isEmpty()) {
            throw new RuntimeException("User not found with id : " + subject);
        }
        User user = userOptional.get();

        Profile profile = new Profile(user.getName(), user.getImageUrl(), "245", "1.2M", "18.5M", "\uD83D\uDC83 Professional dancer | Content creator | LA based \uD83C\uDF34\n" +
                "Bookings: dancequeen@example.com");

        return ResponseEntity.ok(profile);
    }
}
