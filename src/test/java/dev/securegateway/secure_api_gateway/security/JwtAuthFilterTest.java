package dev.securegateway.secure_api_gateway.security;

import io.jsonwebtoken.MalformedJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.context.SecurityContextHolder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

class JwtAuthFilterTest {

    private JwtUtil jwtUtil;
    private JwtAuthFilter filter;
    private FilterChain filterChain;

    @BeforeEach
    void setUp() {
        jwtUtil = mock(JwtUtil.class);
        filter = new JwtAuthFilter(jwtUtil);
        filterChain = mock(FilterChain.class);

        SecurityContextHolder.clearContext();
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void shouldContinueWithoutAuthenticationWhenTokenIsMissing() throws Exception {
        MockHttpServletRequest request =
                new MockHttpServletRequest("GET", "/api/gateway/users");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, filterChain);

        assertThat(SecurityContextHolder.getContext().getAuthentication())
                .isNull();
        verify(filterChain).doFilter(request, response);
        verifyNoInteractions(jwtUtil);
    }

    @Test
    void shouldAuthenticateWhenTokenIsValid() throws Exception {
        MockHttpServletRequest request =
                new MockHttpServletRequest("GET", "/api/gateway/users");
        request.addHeader("Authorization", "Bearer valid-token");

        MockHttpServletResponse response = new MockHttpServletResponse();

        when(jwtUtil.extractUsername("valid-token"))
                .thenReturn("testuser");

        filter.doFilter(request, response, filterChain);

        assertThat(SecurityContextHolder.getContext().getAuthentication())
                .isNotNull();
        assertThat(SecurityContextHolder.getContext().getAuthentication()
                .getName()).isEqualTo("testuser");

        verify(filterChain).doFilter(request, response);
    }

    @Test
    void shouldRejectRequestWhenTokenIsInvalid() throws Exception {
        MockHttpServletRequest request =
                new MockHttpServletRequest("GET", "/api/gateway/users");
        request.addHeader("Authorization", "Bearer invalid-token");

        MockHttpServletResponse response = new MockHttpServletResponse();

        when(jwtUtil.extractUsername("invalid-token"))
                .thenThrow(new MalformedJwtException("Invalid test token"));

        filter.doFilter(request, response, filterChain);

        assertThat(response.getStatus())
                .isEqualTo(HttpServletResponse.SC_UNAUTHORIZED);
        assertThat(response.getHeader("WWW-Authenticate"))
                .isEqualTo("Bearer error=\"invalid_token\"");
        assertThat(SecurityContextHolder.getContext().getAuthentication())
                .isNull();

        verifyNoInteractions(filterChain);
    }
}
