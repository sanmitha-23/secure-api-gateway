package dev.securegateway.secure_api_gateway.config;

import dev.securegateway.secure_api_gateway.security.InputSanitizationFilter;
import dev.securegateway.secure_api_gateway.security.JwtAuthFilter;
import dev.securegateway.secure_api_gateway.security.RateLimitFilter;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain configure(HttpSecurity http, JwtAuthFilter jwtAuthFilter,
                                         InputSanitizationFilter inputSanitizationFilter,
                                         RateLimitFilter rateLimitFilter) throws Exception {
        http
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(inputSanitizationFilter, JwtAuthFilter.class)
                .addFilterAfter(rateLimitFilter, JwtAuthFilter.class)
                .authorizeHttpRequests(authorizeRequests ->
                        authorizeRequests.requestMatchers("/api/auth/**", "/actuator/health",
                                        "/actuator/prometheus").permitAll()
                                .anyRequest().authenticated())
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        return http.build();
    }

    @Bean
    public FilterRegistrationBean<JwtAuthFilter> disableAutoRegistration(JwtAuthFilter filter) {
        FilterRegistrationBean<JwtAuthFilter> bean = new FilterRegistrationBean<>(filter);
        bean.setEnabled(false); // let Spring Security's own chain be the only place this runs
        return bean;
    }

    @Bean
    public FilterRegistrationBean<InputSanitizationFilter> disableAutoRegistration2(InputSanitizationFilter filter) {
        FilterRegistrationBean<InputSanitizationFilter> bean = new FilterRegistrationBean<>(filter);
        bean.setEnabled(false);
        return bean;
    }

    @Bean
    public FilterRegistrationBean<RateLimitFilter> disableAutoRegistration3(RateLimitFilter filter) {
        FilterRegistrationBean<RateLimitFilter> bean = new FilterRegistrationBean<>(filter);
        bean.setEnabled(false);
        return bean;
    }
}
