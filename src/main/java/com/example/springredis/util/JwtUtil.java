package com.example.springredis.util;

import com.example.springredis.domain.User;
import com.example.springredis.repository.UserRepository;
import com.example.springredis.security.UserDetailsServiceImpl;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.Date;

@Getter
@RequiredArgsConstructor
@Component
public class JwtUtil {

    private final String JWT_SECRET = "SECRET";
    private final SignatureAlgorithm SIGNATURE = SignatureAlgorithm.HS256;
    private final UserDetailsServiceImpl userDetailsService;
    public final static long ACCESS_TOKEN_EXP_SECOND = 1000L * 60;
    public final static long REFRESH_TOKEN_EXP_SECOND = 1000L * 180;

    private final UserRepository userRepository;

    public String createAccessToken(String username) {
        Claims claims = Jwts.claims();
        claims.put("username", username);

        return Jwts.builder()
                .setClaims(claims)
                .setExpiration(new Date(System.currentTimeMillis() + ACCESS_TOKEN_EXP_SECOND))
                .signWith(SIGNATURE, JWT_SECRET)
                .compact();
    }

    public String createRefreshToken(String username) {
        Claims claims = Jwts.claims();
        claims.put("username", username);

        return Jwts.builder()
                .setClaims(claims)
                .setExpiration(new Date(System.currentTimeMillis() + REFRESH_TOKEN_EXP_SECOND))
                .signWith(SIGNATURE, JWT_SECRET)
                .compact();
    }

    public String getUsername(String token) {
        Claims claims = getAllClaims(token);
        return String.valueOf(claims.get("username"));
    }

    public boolean isValidToken(String token){

        Claims claims = getAllClaims(token);

        Date expiration = claims.getExpiration();
        String username = String.valueOf(claims.get("username"));

        return expiration.after(new Date()) && userDetailsService.loadUserByUsername(username) != null;
    }

    private Claims getAllClaims(String token) {
        return Jwts.parser()
                .setSigningKey(JWT_SECRET)
                .parseClaimsJws(token)
                .getBody();
    }
}
