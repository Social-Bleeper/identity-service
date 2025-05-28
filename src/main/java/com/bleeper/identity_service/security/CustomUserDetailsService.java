package com.bleeper.identity_service.security;

import com.bleeper.identity_service.exceptions.ResourceNotFoundException;
import com.bleeper.identity_service.models.User;
import com.bleeper.identity_service.repositories.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

@RequiredArgsConstructor
@Service
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    @Transactional
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() ->
                        new UsernameNotFoundException("User not found with email : " + email)
                );

        return UserPrincipal.create(user);
    }

    @Transactional
    public UserDetails loadUserByPublicId(Long publicId) {
        User user = userRepository.findById(publicId)
                .orElseThrow(() ->
                        new ResourceNotFoundException("User", "publicId", publicId)
                );

        return UserPrincipal.create(user);
    }
}
