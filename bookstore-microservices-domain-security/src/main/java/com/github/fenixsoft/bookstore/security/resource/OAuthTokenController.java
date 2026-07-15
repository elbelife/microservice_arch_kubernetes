package com.github.fenixsoft.bookstore.security.resource;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.*;

/**
 * 自定义 OAuth2 Token Endpoint 控制器 (替代 Spring Security OAuth2 的 legacy /oauth/token 端点)
 *
 * @author/date 2026/07/16
 **/
@RestController
@RequestMapping("/oauth")
public class OAuthTokenController {

    @Autowired
    private AuthenticationManager authenticationManager;

    private static final String JWT_TOKEN_SIGNING_PRIVATE_KEY = "601304E0-8AD4-40B0-BD51-0B432DC47461";

    @RequestMapping(value = "/token", method = {RequestMethod.GET, RequestMethod.POST})
    public ResponseEntity<?> token(
            @RequestParam("grant_type") String grantType,
            @RequestParam(value = "client_id", required = false) String clientId,
            @RequestParam(value = "client_secret", required = false) String clientSecret,
            @RequestParam(value = "username", required = false) String username,
            @RequestParam(value = "password", required = false) String password,
            @RequestParam(value = "refresh_token", required = false) String refreshTokenParam) {

        try {
            if ("password".equalsIgnoreCase(grantType)) {
                Authentication auth = authenticationManager.authenticate(
                        new UsernamePasswordAuthenticationToken(username, password)
                );
                UserDetails userDetails = (UserDetails) auth.getPrincipal();
                String[] authorities = userDetails.getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority)
                        .toArray(String[]::new);

                String accessToken = generateJwt(username, authorities, "BROWSER", 3600 * 3);
                String refreshToken = generateJwt(username, authorities, "BROWSER", 3600 * 24 * 15);
                Map<String, Object> response = new HashMap<>();
                response.put("access_token", accessToken);
                response.put("refresh_token", refreshToken);
                response.put("token_type", "bearer");
                response.put("expires_in", 3600 * 3);
                response.put("scope", "BROWSER");
                return ResponseEntity.ok(response);

            } else if ("client_credentials".equalsIgnoreCase(grantType)) {
                String token = generateJwt(clientId != null ? clientId : "service", new String[]{}, "SERVICE", 3600 * 3);
                Map<String, Object> response = new HashMap<>();
                response.put("access_token", token);
                response.put("token_type", "bearer");
                response.put("expires_in", 3600 * 3);
                response.put("scope", "SERVICE");
                return ResponseEntity.ok(response);

            } else if ("refresh_token".equalsIgnoreCase(grantType)) {
                SignedJWT signedJWT = SignedJWT.parse(refreshTokenParam);
                com.nimbusds.jose.JWSVerifier verifier = new com.nimbusds.jose.crypto.MACVerifier(JWT_TOKEN_SIGNING_PRIVATE_KEY);
                if (!signedJWT.verify(verifier)) {
                    throw new IllegalArgumentException("Invalid signature");
                }
                JWTClaimsSet claims = signedJWT.getJWTClaimsSet();
                if (new Date().after(claims.getExpirationTime())) {
                    throw new IllegalArgumentException("Token expired");
                }
                String subject = claims.getSubject();
                List<String> authList = claims.getStringListClaim("authorities");
                String[] authorities = authList != null ? authList.toArray(String[]::new) : new String[]{};

                String accessToken = generateJwt(subject, authorities, "BROWSER", 3600 * 3);
                String newRefreshToken = generateJwt(subject, authorities, "BROWSER", 3600 * 24 * 15);
                Map<String, Object> response = new HashMap<>();
                response.put("access_token", accessToken);
                response.put("refresh_token", newRefreshToken);
                response.put("token_type", "bearer");
                response.put("expires_in", 3600 * 3);
                response.put("scope", "BROWSER");
                return ResponseEntity.ok(response);
            }
            
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of("error", "unsupported_grant_type"));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error", "invalid_grant", "error_description", e.getMessage()));
        }
    }

    private String generateJwt(String subject, String[] authorities, String scope, long expirationSeconds) throws Exception {
        JWSSigner signer = new MACSigner(JWT_TOKEN_SIGNING_PRIVATE_KEY);
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject(subject)
                .issueTime(new Date())
                .expirationTime(new Date(System.currentTimeMillis() + expirationSeconds * 1000))
                .claim("user_name", subject)
                .claim("username", subject)
                .claim("authorities", authorities)
                .claim("scope", scope)
                .build();

        SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claimsSet);
        signedJWT.sign(signer);
        return signedJWT.serialize();
    }
}
