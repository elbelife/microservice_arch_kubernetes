package com.github.fenixsoft.bookstore.infrastructure.configuration;

import com.github.fenixsoft.bookstore.domain.security.AuthenticAccountDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.SecurityFilterChain;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * Spring Security 6 资源服务器配置
 *
 * @author icyfenix@gmail.com
 * @date 2026/07/16
 **/
@Configuration
@EnableMethodSecurity(prePostEnabled = true, jsr250Enabled = true)
public class ResourceServerConfiguration {

    @Autowired
    private AuthenticAccountDetailsService userDetailsService;

    private static final String JWT_TOKEN_SIGNING_PRIVATE_KEY = "601304E0-8AD4-40B0-BD51-0B432DC47461";

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        http.csrf(csrf -> csrf.disable());
        http.headers(headers -> headers.frameOptions(frame -> frame.disable()));
        http.authorizeHttpRequests(auth -> auth.anyRequest().permitAll());
        http.oauth2ResourceServer(oauth -> oauth.jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthenticationConverter())));
        return http.build();
    }

    @Bean
    public JwtDecoder jwtDecoder() {
        byte[] keyBytes = JWT_TOKEN_SIGNING_PRIVATE_KEY.getBytes();
        SecretKey secretKey = new SecretKeySpec(keyBytes, 0, keyBytes.length, "AES");
        return NimbusJwtDecoder.withSecretKey(secretKey).build();
    }

    private Converter<Jwt, ? extends AbstractAuthenticationToken> jwtAuthenticationConverter() {
        return jwt -> {
            String username = jwt.getClaimAsString("user_name");
            if (username == null) {
                username = jwt.getClaimAsString("username");
            }
            if (username == null) {
                username = jwt.getSubject();
            }
            UserDetails userDetails = userDetailsService.loadUserByUsername(username);
            return new UsernamePasswordAuthenticationToken(userDetails, jwt, userDetails.getAuthorities());
        };
    }
}
