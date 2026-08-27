package com.example.SpringSecuriity.controller;

import com.example.SpringSecuriity.config.security.JwtUtil;
import com.example.SpringSecuriity.dto.LoginUserDTO;
import com.example.SpringSecuriity.dto.RegisterUserDTO;
import com.example.SpringSecuriity.entity.Role;
import com.example.SpringSecuriity.entity.User;
import com.example.SpringSecuriity.service.RegisterUserService;
import com.example.SpringSecuriity.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import java.util.Set;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

    private final UserService userService;
    private final RegisterUserService registerUserService;
    private final JwtUtil jwtUtil;
    private final AuthenticationManager authenticationManager;

    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@RequestBody RegisterUserDTO registerUserDTO) {
        System.out.println("test1");
        User user = registerUserService.registerUser(registerUserDTO.getEmail(), registerUserDTO.getPassword());
        return ResponseEntity.ok(user);
    }

    @PostMapping("/login")
    public ResponseEntity<?> loginUser(@RequestBody LoginUserDTO loginUserDTO) {
        System.out.println("test2");
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginUserDTO.getEmail(), loginUserDTO.getPassword())
        );

        UserDetails userDetails = userService.loadUserByUsername(loginUserDTO.getEmail());

        Set<Role> roles = userDetails.getAuthorities().stream().map(auth -> Role.valueOf(auth.getAuthority())).collect(Collectors.toSet());

        String token = jwtUtil.generateToken(
                userDetails.getUsername(),
                roles);

        return ResponseEntity.ok(token);
    }
}