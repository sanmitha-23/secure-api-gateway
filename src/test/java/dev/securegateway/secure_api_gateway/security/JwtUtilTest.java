package dev.securegateway.secure_api_gateway.security;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

public class JwtUtilTest {

    @Test
    public void testGenerateToken() {
        /*NOTE: this is a throwaway secret used only to test JwtUtil in isolation. It's intentionally unrelated to the
        app's real JWT_SECRET — this test doesn't load Spring context, so it never touches the actual running config.*/
        JwtUtil util = new JwtUtil("P8Jc/mcuNnaPR+5abSPDbbLTe4o2sRYte8U5md19t2M=", 500000L);
        String token = util.generateToken("testuser");
        assertThat(token).isNotNull();
        assertThat(token.split("\\.")).hasSize(3);
        System.out.println(token);
    }
}
