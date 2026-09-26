package dev.securegateway.secure_api_gateway.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
public class HomeController {

    @GetMapping("/")
    public Map<String, Object> home() {
        return Map.of(
                "name", "Secure API Gateway",
                "status", "running",
                "docs", "https://github.com/sanmitha-23/secure-api-gateway",
                "health", "/actuator/health"
        );
    }
}