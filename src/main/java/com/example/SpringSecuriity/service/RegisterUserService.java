package com.example.SpringSecuriity.service;

import com.example.SpringSecuriity.entity.User;
import com.example.SpringSecuriity.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class RegisterUserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public User registerUser(String email, String password) {
        if(userRepository.existsByEmail(email)) {
            throw new RuntimeException("Email Already Exists");
        }
        User user = new User();
        user.setEmail(email);
        user.setPassword(passwordEncoder.encode(password));
        System.out.println(user.getPassword());
        return userRepository.save(user);
    }

    public User findByEmail(String email) {
        return userRepository.findByEmail(email).orElseThrow(() -> new UsernameNotFoundException("User not found"));
    }
}