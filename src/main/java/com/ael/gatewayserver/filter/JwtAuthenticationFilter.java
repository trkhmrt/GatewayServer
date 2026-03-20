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

            // Token'ı doğrula
            if (!jwtUtil.validateToken(token)) {
                logger.warn("Invalid token provided");
                return onError(exchange, "Invalid token", HttpStatus.UNAUTHORIZED);
            }


            try {
                Integer userId = jwtUtil.extractUserId(token);

                if(userId == null) {
                    logger.warn("Failed to extract required information from token");
                    return onError(exchange, "Invalid token content", HttpStatus.UNAUTHORIZED);
                }

                logger.debug("Token validated successfully for userId: {}",userId);

                // Request header'larına bilgileri ekle
                ServerHttpRequest modifiedRequest = request.mutate()
                        .header("X-User-Role", jwtUtil.extractRole(token))
                        .header("X-User-Id", userId.toString())
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