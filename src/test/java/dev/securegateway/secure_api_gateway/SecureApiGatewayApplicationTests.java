package dev.securegateway.secure_api_gateway;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest(properties = {
        "demo.username=test-demo-user",
        "demo.password=test-only-password",
        "security.jwt.secret=test-only-secret-key-for-spring-context-tests-32-bytes",
        "security.jwt.expiration-ms=3600000"
})
class SecureApiGatewayApplicationTests {

    @Test
    void contextLoads() {
    }

}
