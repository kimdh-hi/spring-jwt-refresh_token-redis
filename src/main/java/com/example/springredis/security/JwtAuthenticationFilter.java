package com.example.springredis.security;

import com.example.springredis.util.JwtUtil;
import com.example.springredis.util.RedisUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Objects;

@RequiredArgsConstructor
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final UserDetailsServiceImpl userDetailsService;
    private final JwtUtil jwtUtil;
    private final RedisUtil redisUtil;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String accessTokenHeader = request.getHeader("ACCESS_TOKEN");
        String accessToken = getToken(accessTokenHeader);

        // 엑세스 토큰이 유효한 경우 => 인증처리
        if (!Objects.isNull(accessToken) && jwtUtil.isValidToken(accessToken)) {
            String username = jwtUtil.getUsername(accessToken);

            UserDetails userDetails = userDetailsService.loadUserByUsername(username);
            UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
            authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
            SecurityContextHolder.getContext().setAuthentication(authToken);

        } else { // 엑세스 토큰이 유효하지 않은 경우 => 리프레쉬 토큰 검증
            String refreshTokenHeader = request.getHeader("REFRESH_TOKEN");
            String refreshToken = getToken(refreshTokenHeader);
            // 엑세스 토큰이 유효하지 않을 때 리프레쉬 토큰은 유효한 경우 => 새로운 엑세스 토큰 생성 및 인증처리
            if (!Objects.isNull(refreshToken) && jwtUtil.isValidToken(refreshToken) && !Objects.isNull(redisUtil.getValue("refreshToken"))) {
                String username = jwtUtil.getUsername(refreshToken);
                String newAccessToken = jwtUtil.createAccessToken(username);

                request.setAttribute("NEW_ACCESS_TOKEN", newAccessToken);

                UserDetails userDetails = userDetailsService.loadUserByUsername(username);
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }
        filterChain.doFilter(request, response);
    }

    private String getToken(String header) {
        if (!Objects.isNull(header) && header.startsWith("Bearer ")) {
            return header.substring(7);
        }
        return null;
    }
}
