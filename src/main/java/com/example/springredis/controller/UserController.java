package com.example.springredis.controller;

import com.example.springredis.dto.JwtTokenDto;
import com.example.springredis.dto.LoginRequestDto;
import com.example.springredis.dto.SignupRequestDto;
import com.example.springredis.security.UserDetailsServiceImpl;
import com.example.springredis.service.UserService;
import com.example.springredis.util.JwtUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@Slf4j
public class UserController {

    private final UserService userService;
    private final AuthenticationManager authenticationManager;
    private final UserDetailsServiceImpl userDetailsService;
    private final JwtUtil jwtUtil;

    @PostMapping("/signup")
    public ResponseEntity signup(@RequestBody SignupRequestDto signupRequestDto) {
        userService.signup(signupRequestDto);

        return ResponseEntity.ok("success");
    }

    @PostMapping("/login")
    public ResponseEntity login(@RequestBody LoginRequestDto loginRequestDto) {
        try {
            UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(loginRequestDto.getUsername(), loginRequestDto.getPassword());
            authenticationManager.authenticate(authenticationToken);
        } catch (BadCredentialsException e) {
            throw new BadCredentialsException("로그인 실패");
        }

        UserDetails userDetails = userDetailsService.loadUserByUsername(loginRequestDto.getUsername());
        String accessToken = jwtUtil.createAccessToken(userDetails.getUsername());
        String refreshToken = jwtUtil.createRefreshToken(userDetails.getUsername());

        return ResponseEntity.ok(new JwtTokenDto(accessToken, refreshToken));
    }
}
