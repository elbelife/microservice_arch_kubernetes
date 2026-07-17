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
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import java.util.List;
import java.util.ArrayList;
import java.util.Collection;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * Spring Security 6 资源服务器配置
 *
 * @author icyfenix@gmail.com
 * @date 2026/07/16
 **/
@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true, jsr250Enabled = false)
public class ResourceServerConfiguration {

    public ResourceServerConfiguration() {
        System.out.println("DEBUG_SECURITY - ResourceServerConfiguration constructor called!");
    }

    @Autowired
    private AuthenticAccountDetailsService userDetailsService;

    private static final String JWT_TOKEN_SIGNING_PRIVATE_KEY = "601304E0-8AD4-40B0-BD51-0B432DC47461";

    @Bean
    public SecurityFilterChain resourceServerSecurityFilterChain(HttpSecurity http) throws Exception {
        http.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        http.csrf(csrf -> csrf.disable());
        http.headers(headers -> headers.frameOptions(frame -> frame.disable()));
        http.authorizeHttpRequests(auth -> auth.anyRequest().permitAll());
        http.servletApi(servletApi -> servletApi.rolePrefix(""));
        http.oauth2ResourceServer(oauth -> {
            oauth.bearerTokenResolver(request -> {
                String header = request.getHeader("Authorization");
                if (header != null) {
                    if (header.regionMatches(true, 0, "bearer ", 0, 7)) {
                        return header.substring(7);
                    }
                }
                return null;
            });
            oauth.jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthenticationConverter()));
        });
        return http.build();
    }

    @Bean
    public JwtDecoder jwtDecoder() {
        byte[] keyBytes = JWT_TOKEN_SIGNING_PRIVATE_KEY.getBytes();
        SecretKey secretKey = new SecretKeySpec(keyBytes, 0, keyBytes.length, "HmacSHA256");
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

            // Reconstruct AuthenticAccount directly from JWT claims to remain completely stateless
            // and avoid database lookup loops over Feign/HTTP.
            com.github.fenixsoft.bookstore.domain.security.AuthenticAccount userDetails = new com.github.fenixsoft.bookstore.domain.security.AuthenticAccount();
            userDetails.setUsername(username);
            userDetails.setPassword(""); // password is not needed for authenticated principal

            if (jwt.hasClaim("id")) {
                Object idVal = jwt.getClaim("id");
                if (idVal instanceof Number) {
                    userDetails.setId(((Number) idVal).intValue());
                }
                userDetails.setName(jwt.getClaimAsString("name"));
                userDetails.setAvatar(jwt.getClaimAsString("avatar"));
                userDetails.setTelephone(jwt.getClaimAsString("telephone"));
                userDetails.setEmail(jwt.getClaimAsString("email"));
                userDetails.setLocation(jwt.getClaimAsString("location"));
            } else {
                // Machine M2M token: fallback values
                userDetails.setId(-1);
                userDetails.setName(username);
            }

            List<GrantedAuthority> authorities = new ArrayList<>();
            
            // Extract authorities from JWT
            Object jwtAuthorities = jwt.getClaim("authorities");
            if (jwtAuthorities instanceof Collection) {
                for (Object auth : (Collection<?>) jwtAuthorities) {
                    authorities.add(new SimpleGrantedAuthority(auth.toString()));
                }
            } else if (jwtAuthorities instanceof String) {
                authorities.add(new SimpleGrantedAuthority((String) jwtAuthorities));
            } else if (jwtAuthorities instanceof String[]) {
                for (String auth : (String[]) jwtAuthorities) {
                    authorities.add(new SimpleGrantedAuthority(auth));
                }
            }

            // Extract scopes from JWT
            Object scopes = jwt.getClaim("scope");
            if (scopes instanceof Collection) {
                for (Object scope : (Collection<?>) scopes) {
                    authorities.add(new SimpleGrantedAuthority("SCOPE_" + scope.toString()));
                }
            } else if (scopes instanceof String) {
                authorities.add(new SimpleGrantedAuthority("SCOPE_" + scopes));
            }

            userDetails.setAuthorities(authorities);

            return new UsernamePasswordAuthenticationToken(userDetails, jwt, authorities);
        };
    }
}
