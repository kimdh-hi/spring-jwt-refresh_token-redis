package com.example.springredis.service;

import com.example.springredis.domain.User;
import com.example.springredis.domain.UserRole;
import com.example.springredis.dto.SignupRequestDto;
import com.example.springredis.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public void signup(SignupRequestDto signupRequestDto) {
        User user = new User(
                signupRequestDto.getUsername(),
                passwordEncoder.encode(signupRequestDto.getPassword()),
                signupRequestDto.isAdmin() ? UserRole.ROLE_ADMIN : UserRole.ROLE_USER
        );

        userRepository.save(user);
    }
}
