package com.example.springredis.controller;

import com.example.springredis.domain.User;
import com.example.springredis.dto.JwtTokenDto;
import com.example.springredis.dto.LoginRequestDto;
import com.example.springredis.dto.SignupRequestDto;
import com.example.springredis.security.UserDetailsImpl;
import com.example.springredis.security.UserDetailsServiceImpl;
import com.example.springredis.service.UserService;
import com.example.springredis.util.JwtUtil;
import com.example.springredis.util.RedisUtil;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@RestController
@RequiredArgsConstructor
@Slf4j
public class UserController {

    private final UserService userService;
    private final AuthenticationManager authenticationManager;
    private final UserDetailsServiceImpl userDetailsService;
    private final JwtUtil jwtUtil;
    private final RedisUtil redisUtil;

    @PostMapping("/signup")
    public ResponseEntity signup(@RequestBody SignupRequestDto signupRequestDto) {
        log.info("signup = {}", signupRequestDto);
        userService.signup(signupRequestDto);

        return ResponseEntity.ok("success");
    }

    @PostMapping("/login")
    public ResponseEntity login(
            @RequestBody LoginRequestDto loginRequestDto,
            HttpServletResponse response
    ) {

        log.info("login = {}", loginRequestDto);

        try {
            UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(loginRequestDto.getUsername(), loginRequestDto.getPassword());
            authenticationManager.authenticate(authenticationToken);
        } catch (BadCredentialsException e) {
            throw new BadCredentialsException("로그인 실패");
        }

        UserDetails userDetails = userDetailsService.loadUserByUsername(loginRequestDto.getUsername());
        String accessToken = jwtUtil.createAccessToken(userDetails.getUsername());
        String refreshToken = jwtUtil.createRefreshToken(userDetails.getUsername());

        log.info("access-Token = {}", accessToken);
        log.info("refresh-token = {}", refreshToken);

        response.setHeader("ACCESS_TOKEN", accessToken);
        response.setHeader("REFRESH_TOKEN", refreshToken);
        redisUtil.setValue(refreshToken, userDetails.getUsername(), JwtUtil.REFRESH_TOKEN_EXP_SECOND);

        return ResponseEntity.ok("로그인 성공");
    }

    @Secured({"ROLE_USER, ROLE_ADMIN"})
    @GetMapping("/auth")
    public String authCheck(
            @AuthenticationPrincipal UserDetailsImpl userDetails
    ) {
        User user = userDetails.getUser();

        return user.getUsername() + "환영합니다.";
    }

}
