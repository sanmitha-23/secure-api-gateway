package dev.securegateway.secure_api_gateway.security;

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import jakarta.servlet.FilterChain;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

public class InputSanitizationFilterTest {
    private InputSanitizationFilter filter;
    private FilterChain filterChain;

    @BeforeEach
    void setUp() {
        filter = new InputSanitizationFilter(new SimpleMeterRegistry());
        filterChain = mock(FilterChain.class);
    }

    @Test
    void shouldRejectUnquotedSqlInjectionTautology() throws Exception {
        MockHttpServletRequest request =
                new MockHttpServletRequest("GET", "/api/gateway/users");
        request.setQueryString("id=1%20OR%201=1");
        request.addParameter("id", "1 OR 1=1");

        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, filterChain);

        assertThat(response.getStatus()).isEqualTo(400);
        verifyNoInteractions(filterChain);
    }

    @Test
    void shouldAllowNormalNumericParameter() throws Exception {
        MockHttpServletRequest request =
                new MockHttpServletRequest("GET", "/api/gateway/users");
        request.addParameter("id", "123");

        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, filterChain);

        assertThat(response.getStatus()).isEqualTo(200);
        verify(filterChain).doFilter(request, response);
    }
}
