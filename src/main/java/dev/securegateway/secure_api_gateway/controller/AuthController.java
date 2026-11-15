package dev.securegateway.secure_api_gateway.controller;

import dev.securegateway.secure_api_gateway.security.JwtUtil;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class AuthController {
    private final JwtUtil jwtUtil;
    private final String demoUsername;
    private final String demoPassword;

    public AuthController(
            JwtUtil jwtUtil,
            @Value("${demo.username}") String demoUsername,
            @Value("${demo.password}") String demoPassword) {
        this.jwtUtil = jwtUtil;
        this.demoUsername = demoUsername;
        this.demoPassword = demoPassword;
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody Map<String, String> body) {
        String username = body.get("username");
        String password = body.get("password");

        if (!demoUsername.equals(username) || !demoPassword.equals(password)) {
            return ResponseEntity.status(401)
                    .body(Map.of("error", "Invalid credentials"));
        }

        String token = jwtUtil.generateToken(username);
        return ResponseEntity.ok(Map.of("token", token));
    }
}
