package dev.securegateway.secure_api_gateway.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.commons.text.StringEscapeUtils;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

@Component
public class InputSanitizationFilter extends OncePerRequestFilter {

    private static final Pattern HTML_TAG_PATTERN = Pattern.compile("<\\s*[a-zA-Z!/]");

    private static final List<Pattern> SQLI_PATTERNS = List.of(
            // Quote followed by a boolean tautology: ' OR '1'='1  or  ' or 1=1
            Pattern.compile("(?i)'\\s*(or|and)\\s+('[^']*'?|\\d+)\\s*=\\s*('[^']*'?|\\d+)"),

            // SQL comment sequence used to truncate a query, appearing right after
            // a quote or semicolon (not just "--" anywhere, which could be legitimate text)
            Pattern.compile("(?i)['\";]\\s*(--|#|/\\*)"),

            // Stacked query: a semicolon followed by a destructive/DDL statement
            Pattern.compile("(?i);\\s*(drop|delete|update|insert|alter|exec|union)\\s"),

            // Classic UNION-based exfiltration shape
            Pattern.compile("(?i)\\bunion\\s+(all\\s+)?select\\b")
    );

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        String contentType = request.getContentType();
        boolean isMultipart = contentType != null && contentType.contains("multipart/form-data");

        // 1. Check every query parameter, on every request method.
        if (!isMultipart) {
            for (Map.Entry<String, String[]> entry : request.getParameterMap().entrySet()) {
                for (String value : entry.getValue()) {
                    if (isDangerous(value)) {
                        response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                        response.getWriter().write("Request rejected: potentially malicious input detected.");
                        return; // short-circuit — do NOT call filterChain.doFilter
                    }
                }
            }
        }

        // 2. For POST/PUT, also check the body — and use the wrapper so the
        // controller can still read it afterward.
        String method = request.getMethod();
        if ((method.equals("POST") || method.equals("PUT")) && !isMultipart) {
            CachedBodyHttpServletRequest wrappedRequest = new CachedBodyHttpServletRequest(request);
            String body = wrappedRequest.getCachedBodyAsString();

            if (isDangerous(body)) {
                response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                response.getWriter().write("Request rejected: potentially malicious input detected.");
                return;
            }

            filterChain.doFilter(wrappedRequest, response); // pass the WRAPPED request onward
            return;
        }

        filterChain.doFilter(request, response);
    }

    private boolean isDangerous(String rawInput) {
        String canonicalized = canonicalize(rawInput);

        // If the sanitized output does NOT equal the original canonicalized
        // string, dangerous markup was present — return true.
        if (HTML_TAG_PATTERN.matcher(canonicalized).find()) {
            return true;
        }

        // check `canonicalized` against a SMALL, high-confidence
        // set of genuine attack syntax — NOT common words. Think about actual
        // injection shapes: a quote followed by a boolean tautology
        // (' OR '1'='1), SQL comment sequences used to truncate a query
        // (-- or /*), stacked queries (;). Write 2-3 regexes for these
        // SPECIFIC shapes, not single keywords like "SELECT" or "OR" alone —
        // that's exactly the mistake that caused your false positives before.
        for (Pattern pattern : SQLI_PATTERNS) {
            if (pattern.matcher(canonicalized).find()) {
                return true;
            }
        }

        return false; // replace with real logic
    }

    private String canonicalize(String input) {
        if (input == null) return "";
        String decoded = input;
        try {
            // Decode URL-encoding repeatedly until it stabilizes, catching
            // double-encoding tricks.
            String previous;
            do {
                previous = decoded;
                decoded = URLDecoder.decode(decoded, StandardCharsets.UTF_8);
            } while (!decoded.equals(previous));
        } catch (Exception e) {
            // malformed encoding — treat cautiously, don't crash
        }
        return StringEscapeUtils.unescapeHtml4(decoded);
    }
}