package com.github.fenixsoft.bookstore.infrastructure.configuration;

import feign.Contract;
import feign.RequestInterceptor;
import feign.jaxrs3.JAXRS3Contract;
import org.springframework.cloud.openfeign.EnableFeignClients;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.jwt.Jwt;

/**
 * 启动FeignClient扫描，并配置：
 * 1. 并指定包包扫描地址
 * 2. 设置交互为JAX-RS3方式以支持Jakarta REST
 * 3. 自动传播 JWT Bearer 令牌以实现微服务间认证
 *
 * @author icyfenix@gmail.com
 * @date 2020/4/18 22:38
 **/
@Configuration
@Profile("!test")
@EnableFeignClients(basePackages = {"com.github.fenixsoft.bookstore"})
public class FeignConfiguration {

    @Bean
    public Contract feignContract() {
        return new JAXRS3Contract();
    }

    @Bean
    public RequestInterceptor oauth2FeignRequestInterceptor() {
        return requestTemplate -> {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            if (authentication != null && authentication.getPrincipal() instanceof UserDetails) {
                // If we need the token value, we can extract it if authentication credentials holds the Jwt
                if (authentication.getCredentials() instanceof Jwt) {
                    Jwt jwt = (Jwt) authentication.getCredentials();
                    requestTemplate.header("Authorization", "Bearer " + jwt.getTokenValue());
                }
            } else if (authentication != null && authentication.getCredentials() instanceof Jwt) {
                Jwt jwt = (Jwt) authentication.getCredentials();
                requestTemplate.header("Authorization", "Bearer " + jwt.getTokenValue());
            }
        };
    }

}
