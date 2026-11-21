package dev.securegateway.secure_api_gateway.security;

import io.jsonwebtoken.JwtException;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

public class JwtUtilTest {

    // Test-only secret; never use this in the application.
    private static final String TEST_SECRET =
            "test-only-secret-key-for-jwt-unit-tests-32-bytes-minimum";

    @Test
    void shouldGenerateAndExtractUsernameFromToken() {
        JwtUtil util = new JwtUtil(TEST_SECRET, 500000L);

        String token = util.generateToken("testuser");

        assertThat(token).isNotNull();
        assertThat(token.split("\\.")).hasSize(3);
        assertThat(util.extractUsername(token)).isEqualTo("testuser");
    }

    @Test
    void shouldRejectTokenWithTamperedSignature() {
        JwtUtil util = new JwtUtil(TEST_SECRET, 500000L);

        String token = util.generateToken("testuser");

        String[] parts = token.split("\\.");
        char firstSignatureChar = parts[2].charAt(0);
        char tamperedChar = firstSignatureChar == 'a' ? 'b' : 'a';

        parts[2] = tamperedChar + parts[2].substring(1);
        String tamperedToken = String.join(".", parts);

        assertThatThrownBy(() -> util.extractUsername(tamperedToken))
                .isInstanceOf(JwtException.class);
    }

}
