package com.example.SpringSecuriity.config.security;

import com.example.SpringSecuriity.service.UserService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JwtAuthFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;
    private final UserService userService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        final String authHeader = request.getHeader("Authorization");
        String jwt = null;
        String email = null;
        if(authHeader != null && authHeader.startsWith("Bearer ")) {
            jwt = authHeader.substring(7);
            if(jwt == null || jwt.trim().isEmpty()) {
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.getWriter().write("Invalid token");
                return;
            }

            try {
                email = jwtUtil.extractEmailFromClaims(jwt);
            } catch (Exception e) {
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.getWriter().write("Invalid JWT token");
                return;
            }

            if(email != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                UserDetails userDetails = userService.loadUserByUsername(email);
                try {
                    if(jwtUtil.validateToken(jwt, userDetails)) {
                        UsernamePasswordAuthenticationToken authenticationToken
                                = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());

                        authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                        SecurityContextHolder.getContext().setAuthentication(authenticationToken);
                    } else {
                        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                        response.getWriter().write("Invalid JWT token");
                        return;
                    }
                } catch (Exception e) {
                    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                    response.getWriter().write("Invalid JWT token");
                    return;
                }
            }

            filterChain.doFilter(request, response);
        }
    }
}