package com.ael.gatewayserver.filter;


import com.ael.gatewayserver.util.JwtUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpCookie;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
public class JwtAuthenticationFilter extends AbstractGatewayFilterFactory<JwtAuthenticationFilter.Config> {

    private static final Logger logger = LoggerFactory.getLogger(JwtAuthenticationFilter.class);


    private final JwtUtil jwtUtil;
    


    public JwtAuthenticationFilter(JwtUtil jwtUtil) {
        super(Config.class);
        this.jwtUtil = jwtUtil;

    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {

            ServerHttpRequest request = exchange.getRequest();

            final String token = extractToken(request);

            if (token == null || token.isEmpty()) {
                return onError(exchange, "Missing or empty token", HttpStatus.UNAUTHORIZED);
            }

            // Önce Authorization header'ı kontrol et
            String authHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
            if (authHeader != null && authHeader.startsWith("Bearer ")) {


                if (token.isEmpty()) {
                    logger.warn("Empty token found in Authorization header");
                    return onError(exchange, "Empty token", HttpStatus.UNAUTHORIZED);
                }

                logger.debug("Token found in Authorization header.");
            }

            // Token'ı doğrula
            if (!jwtUtil.validateToken(token)) {
                logger.warn("Invalid token provided");
                return onError(exchange, "Invalid token", HttpStatus.UNAUTHORIZED);
            }

            // 3. Token'dan UUID'yi çıkar
            String uuid = jwtUtil.extractUUID(token);
            if (uuid == null) {
                logger.warn("UUID not found in token");
                return onError(exchange, "Invalid token content", HttpStatus.UNAUTHORIZED);
            }

            try {
                // Token'dan bilgileri çıkar
                String username = jwtUtil.extractUsername(token);
                String role = jwtUtil.extractRole(token);
                Integer customerId = jwtUtil.extractCustomerId(token);

                if(username == null || customerId == null) {
                    logger.warn("Failed to extract required information from token");
                    return onError(exchange, "Invalid token content", HttpStatus.UNAUTHORIZED);
                }

                logger.debug("Token validated successfully for user: {}, role: {}, customerId: {}", username, role, customerId);

                // Request header'larına bilgileri ekle
                ServerHttpRequest modifiedRequest = request.mutate()
                        .header("X-User-Name", username)
                        .header("X-User-Role", role)
                        .header("X-Customer-Id", customerId.toString())
                        .build();


                return chain.filter(exchange.mutate().request(modifiedRequest).build());

            } catch (Exception e) {
                logger.error("Token validation failed: {}", e.getMessage(), e);
                return onError(exchange, "Token validation failed", HttpStatus.UNAUTHORIZED);
            }
        };
    }

    private Mono<Void> onError(ServerWebExchange exchange, String err, HttpStatus httpStatus) {
        logger.error("JWT Authentication Error: {} - Status: {}", err, httpStatus);
        exchange.getResponse().setStatusCode(httpStatus);
        return exchange.getResponse().setComplete();
    }

    private String extractToken(ServerHttpRequest request) {
        // 1. Authorization Header'dan
        String authHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String token = authHeader.substring(7);
            if (!token.isEmpty()) {
                logger.debug("Token found in Authorization header");
                return token;
            }
        }

        // 2. Cookie'den
        HttpCookie cookie = request.getCookies().getFirst("access_token");
        if (cookie != null && !cookie.getValue().isEmpty()) {
            logger.debug("Token found in cookie");
            return cookie.getValue();
        }

        return null;
    }

    public static class Config {
        // Konfigürasyon ayarları buraya eklenebilir

    }
}