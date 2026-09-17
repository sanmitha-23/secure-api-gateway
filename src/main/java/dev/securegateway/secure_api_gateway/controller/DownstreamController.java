package dev.securegateway.secure_api_gateway.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

@RestController
public class DownstreamController {

    @GetMapping("/internal/users")
    public List<Map<String, Object>> getUsers() {
        return List.of(
                Map.of("id", 1, "name", "Alice"),
                Map.of("id", 2, "name", "Bob")
        );
    }

    @GetMapping("/internal/users/{id}")
    public Map<String, Object> getUser(@PathVariable String id) {
        return Map.of("id", id, "name", "User" + id);
    }
}
