package com.github.fenixsoft.bookstore.infrastructure.configuration;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import feign.Contract;
import feign.RequestInterceptor;
import feign.jaxrs3.JAXRS3Contract;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.openfeign.EnableFeignClients;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.atomic.AtomicReference;

/**
 * 启动FeignClient扫描，并配置：
 * 1. 指定包扫描地址
 * 2. 设置交互为JAX-RS3方式以支持Jakarta REST
 * 3. 自动传播 JWT Bearer 令牌以实现微服务间认证
 *    - 若 SecurityContext 中有用户 JWT（BROWSER 请求），直接转发
 *    - 若无用户 JWT（服务间 M2M 调用），自动以 client_credentials 方式向 security 服务申请 SERVICE 令牌
 *
 * @author icyfenix@gmail.com
 * @date 2020/4/18 22:38
 **/
@Configuration
@Profile("!test")
@EnableFeignClients(basePackages = {"com.github.fenixsoft.bookstore"})
public class FeignConfiguration {

    private static final Logger log = LoggerFactory.getLogger(FeignConfiguration.class);

    /** security 服务地址，在 Kubernetes 中使用 K8s DNS，本地开发时可覆盖 */
    @Value("${feign.oauth2.token-uri:http://security/oauth/token}")
    private String tokenUri;

    @Value("${feign.oauth2.client-id:warehouse}")
    private String clientId;

    @Value("${feign.oauth2.client-secret:warehouse_secret}")
    private String clientSecret;

    // 缓存：token 值 + 过期时刻（提前 60s 刷新）
    private final AtomicReference<CachedToken> cachedToken = new AtomicReference<>(CachedToken.EMPTY);

    @Bean
    public Contract feignContract() {
        return new JAXRS3Contract();
    }

    @Bean
    public RequestInterceptor oauth2FeignRequestInterceptor() {
        return requestTemplate -> {
            // 优先使用 SecurityContext 中的用户 JWT（BROWSER 请求链路）
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            if (authentication != null && authentication.getCredentials() instanceof Jwt) {
                Jwt jwt = (Jwt) authentication.getCredentials();
                requestTemplate.header("Authorization", "Bearer " + jwt.getTokenValue());
                return;
            }

            // 无用户 JWT：M2M 调用，使用 client_credentials 获取 SERVICE 令牌
            String token = getOrRefreshServiceToken();
            if (token != null) {
                requestTemplate.header("Authorization", "Bearer " + token);
            }
        };
    }

    private String getOrRefreshServiceToken() {
        CachedToken current = cachedToken.get();
        if (current.isValid()) {
            return current.token;
        }
        try {
            String body = "grant_type=client_credentials"
                    + "&client_id=" + URLEncoder.encode(clientId, StandardCharsets.UTF_8)
                    + "&client_secret=" + URLEncoder.encode(clientSecret, StandardCharsets.UTF_8);

            HttpClient client = HttpClient.newBuilder()
                    .connectTimeout(Duration.ofSeconds(5))
                    .build();
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(tokenUri))
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .POST(HttpRequest.BodyPublishers.ofString(body))
                    .timeout(Duration.ofSeconds(10))
                    .build();

            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() == 200) {
                JsonNode json = new ObjectMapper().readTree(response.body());
                String token = json.path("access_token").asText(null);
                long expiresIn = json.path("expires_in").asLong(3600);
                if (token != null) {
                    cachedToken.set(new CachedToken(token, Instant.now().plusSeconds(expiresIn - 60)));
                    log.debug("Obtained service token for client '{}'", clientId);
                    return token;
                }
            } else {
                log.warn("Failed to obtain service token from {}: HTTP {}", tokenUri, response.statusCode());
            }
        } catch (Exception e) {
            log.warn("Failed to obtain service token from {}: {}", tokenUri, e.getMessage());
        }
        return null;
    }

    private static class CachedToken {
        static final CachedToken EMPTY = new CachedToken(null, Instant.EPOCH);
        final String token;
        final Instant expiresAt;

        CachedToken(String token, Instant expiresAt) {
            this.token = token;
            this.expiresAt = expiresAt;
        }

        boolean isValid() {
            return token != null && Instant.now().isBefore(expiresAt);
        }
    }
}
