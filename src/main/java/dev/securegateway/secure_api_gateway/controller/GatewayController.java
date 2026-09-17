package dev.securegateway.secure_api_gateway.controller;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClient;

@RestController
@RequestMapping(value = "/api/gateway")
public class GatewayController {

    private final RestClient restClient;

    public GatewayController(@Value("${downstream.base-url}") String downstreamBaseUrl) {
        this.restClient = RestClient.builder()
                .baseUrl(downstreamBaseUrl)
                .build();
    }

    @GetMapping("/users")
    public String proxyListUsers() {
        return restClient.get()
                .uri("/internal/users")
                .retrieve()
                .body(String.class);
    }

    @GetMapping("/users/{id}")
    public String proxyListUser(@PathVariable String id) {
        return restClient.get()
                .uri("/internal/users/{id}", id)
                .retrieve()
                .body(String.class);
    }
}
