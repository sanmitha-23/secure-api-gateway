package dev.securegateway.secure_api_gateway.security;

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import jakarta.servlet.FilterChain;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.Collections;
import java.util.concurrent.atomic.AtomicLong;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

class RateLimitFilterTest {

    private StringRedisTemplate redisTemplate;
    private ValueOperations<String, String> valueOperations;
    private SimpleMeterRegistry meterRegistry;
    private RateLimitFilter filter;
    private FilterChain filterChain;

    @BeforeEach
    void setUp() {
        redisTemplate = mock(StringRedisTemplate.class);
        valueOperations = mock(ValueOperations.class);
        meterRegistry = new SimpleMeterRegistry();
        filterChain = mock(FilterChain.class);

        when(redisTemplate.opsForValue()).thenReturn(valueOperations);

        filter = new RateLimitFilter(redisTemplate, meterRegistry);
    }

    @Test
    void shouldRejectRequestAfterRateLimitIsExceeded() throws Exception {
        AtomicLong requestCount = new AtomicLong();

        when(valueOperations.increment(anyString()))
                .thenAnswer(invocation -> requestCount.incrementAndGet());

        for (int i = 1; i <= 21; i++) {
            MockHttpServletRequest request =
                    new MockHttpServletRequest("GET", "/api/gateway/users");
            request.setRemoteAddr("203.0.113.10");

            MockHttpServletResponse response =
                    new MockHttpServletResponse();

            filter.doFilter(request, response, filterChain);

            if (i <= 20) {
                assertThat(response.getStatus()).isEqualTo(200);
            } else {
                assertThat(response.getStatus()).isEqualTo(429);
                assertThat(response.getHeader("Retry-After"))
                        .isEqualTo("60");
            }
        }

        verify(filterChain, times(20))
                .doFilter(any(), any());

        assertThat(meterRegistry
                .get("gateway.security.blocked")
                .tag("reason", "rate_limit")
                .counter()
                .count()).isEqualTo(1.0);
    }

    @Test
    void shouldSkipRateLimitForLoopbackInternalRequest() throws Exception {
        MockHttpServletRequest request =
                new MockHttpServletRequest("GET", "/internal/health");

        // MockHttpServletRequest defaults to a loopback address.
        MockHttpServletResponse response =
                new MockHttpServletResponse();

        filter.doFilter(request, response, filterChain);

        assertThat(response.getStatus()).isEqualTo(200);

        verify(filterChain).doFilter(request, response);
        verifyNoInteractions(redisTemplate);
    }

    @Test
    void shouldUseUsernameAsRateLimitIdentifierForAuthenticatedRequest()
            throws Exception {

        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken(
                        "testuser", null, Collections.emptyList()));

        MockHttpServletRequest request =
                new MockHttpServletRequest("GET", "/api/gateway/users");
        request.setRemoteAddr("203.0.113.10");

        MockHttpServletResponse response =
                new MockHttpServletResponse();

        filter.doFilter(request, response, filterChain);

        ArgumentCaptor<String> keyCaptor =
                ArgumentCaptor.forClass(String.class);

        verify(valueOperations).increment(keyCaptor.capture());

        assertThat(keyCaptor.getValue())
                .startsWith("ratelimit:user: testuser:");

        verify(filterChain).doFilter(request, response);
    }

    @Test
    void shouldUseIpAddressAsRateLimitIdentifierForUnauthenticatedRequest()
            throws Exception {

        MockHttpServletRequest request =
                new MockHttpServletRequest("GET", "/api/auth/login");
        request.setRemoteAddr("203.0.113.15");

        MockHttpServletResponse response =
                new MockHttpServletResponse();

        filter.doFilter(request, response, filterChain);

        ArgumentCaptor<String> keyCaptor =
                ArgumentCaptor.forClass(String.class);

        verify(valueOperations).increment(keyCaptor.capture());

        assertThat(keyCaptor.getValue())
                .startsWith("ratelimit:ip:203.0.113.15:");

        verify(filterChain).doFilter(request, response);
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }
}
