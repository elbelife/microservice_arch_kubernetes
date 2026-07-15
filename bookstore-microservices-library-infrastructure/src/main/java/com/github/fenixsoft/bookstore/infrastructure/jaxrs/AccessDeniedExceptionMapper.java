package com.github.fenixsoft.bookstore.infrastructure.jaxrs;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.AccessDeniedException;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.ExceptionMapper;
import jakarta.ws.rs.ext.Provider;

/**
 * 用于统一处理在Resource中由于Spring Security授权访问产生的异常信息
 *
 * @author icyfenix@gmail.com
 * @date 2020/4/7 0:09
 **/
@Provider
public class AccessDeniedExceptionMapper implements ExceptionMapper<AccessDeniedException> {

    private static final Logger log = LoggerFactory.getLogger(AccessDeniedExceptionMapper.class);

    @Context
    private HttpServletRequest request;

    @Override
    public Response toResponse(AccessDeniedException exception) {
        org.springframework.security.core.Authentication auth = org.springframework.security.core.context.SecurityContextHolder.getContext().getAuthentication();
        if (auth != null) {
            System.out.println("DEBUG_ACCESS_DENIED - Auth class: " + auth.getClass().getName() + ", principal: " + auth.getPrincipal() + ", authorities: " + auth.getAuthorities() + ", authenticated: " + auth.isAuthenticated());
        } else {
            System.out.println("DEBUG_ACCESS_DENIED - Auth is null!");
        }
        log.warn("越权访问被禁止 {}: {}", request.getMethod(), request.getPathInfo());
        return CommonResponse.send(Response.Status.FORBIDDEN, exception.getMessage());
    }
}
