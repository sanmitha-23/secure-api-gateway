package dev.securegateway.secure_api_gateway.controller;

import dev.securegateway.secure_api_gateway.security.FileUploadValidator;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestClient;
import org.springframework.web.multipart.MultipartFile;

@RestController
@RequestMapping(value = "/api/gateway")
public class GatewayController {

    private final RestClient restClient;
    private final FileUploadValidator fileUploadValidator;
    private static final Logger logger = LoggerFactory.getLogger(GatewayController.class);

    public GatewayController(@Value("${downstream.base-url}") String downstreamBaseUrl,
                             FileUploadValidator fileUploadValidator) {
        this.restClient = RestClient.builder()
                .baseUrl(downstreamBaseUrl)
                .build();
        this.fileUploadValidator = fileUploadValidator;
    }

    @GetMapping("/users")
    public String proxyListUsers(HttpServletRequest request) {
        return restClient.get()
                .uri("/internal/users")
                .header("Authorization", request.getHeader("Authorization"))
                .retrieve()
                .body(String.class);
    }

    @GetMapping("/users/{id}")
    public String proxyListUser(@PathVariable String id, HttpServletRequest request) {
        return restClient.get()
                .uri("/internal/users/{id}", id)
                .header("Authorization", request.getHeader("Authorization"))
                .retrieve()
                .body(String.class);
    }

    @PostMapping("/upload")
    public ResponseEntity<String> uploadFile(@RequestParam("file") MultipartFile file) {
        logger.info("Upload endpoint reached. Uploading file: {}, file size: {}",
                file.getOriginalFilename(), file.getSize());
        FileUploadValidator.ValidationResult result = fileUploadValidator.validate(file);

        if (!result.isValid()) {
            return ResponseEntity.badRequest().body("Rejected: " + result.reason());
        }

        return ResponseEntity.ok("File accepted: " + file.getOriginalFilename()
                + " (" + file.getSize() + " bytes)");
    }
}
