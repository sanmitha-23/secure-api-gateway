package dev.securegateway.secure_api_gateway.security;

import io.micrometer.core.instrument.MeterRegistry;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Duration;
import java.time.Instant;

@Component
public class RateLimitFilter extends OncePerRequestFilter {

    private static final int MAX_REQUESTS_PER_WINDOW = 20;
    private static final Duration WINDOW = Duration.ofSeconds(60);

    private final StringRedisTemplate redisTemplate;
    private final MeterRegistry meterRegistry;

    private static final Logger logger = LoggerFactory.getLogger(RateLimitFilter.class);

    public RateLimitFilter(StringRedisTemplate redisTemplate, MeterRegistry meterRegistry) {
        this.redisTemplate = redisTemplate;
        this.meterRegistry = meterRegistry;
    }

    /**
     * Same contract as for {@code doFilter}, but guaranteed to be
     * just invoked once per request within a single request thread.
     * See {@link #shouldNotFilterAsyncDispatch()} for details.
     * <p>Provides HttpServletRequest and HttpServletResponse arguments instead of the
     * default ServletRequest and ServletResponse ones.
     *
     * @param request
     * @param response
     * @param filterChain
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        if (request.getRequestURI().startsWith("/internal/")) {
            filterChain.doFilter(request, response); // internal calls don't count against the client's limit
            return;
        }

        String identifier = resolveIdentifier(request);
        long windowBucket = Instant.now().getEpochSecond() / WINDOW.getSeconds();
        String key = "ratelimit:" + identifier + ":" + windowBucket;

        Long count = redisTemplate.opsForValue().increment(key);
        logger.debug("RateLimitFilter hit - key: {}, count: {}, URI: {}", key, count, request.getRequestURI());
        if (count != null && count == 1L) {
            redisTemplate.expire(key, WINDOW);  // only set TTL on the first hit in this window
        }

        if (count != null && count > MAX_REQUESTS_PER_WINDOW) {
            response.setStatus(429);
            response.setHeader("Retry-After", String.valueOf(WINDOW.getSeconds()));
            response.getWriter().write("Rate limit exceeded. Try again later.");
            meterRegistry.counter("gateway.security.blocked", "reason", "rate_limit").increment();
            return;
        }

        filterChain.doFilter(request, response);
    }

    private String resolveIdentifier(HttpServletRequest request) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.isAuthenticated() && !"anonymousUser".equals(auth.getPrincipal())) {
            return "user: " + auth.getName();   // per-user limit once identity is known
        }
        return "ip:" + request.getRemoteAddr(); // fallback for unauthenticated requests
    }
}
