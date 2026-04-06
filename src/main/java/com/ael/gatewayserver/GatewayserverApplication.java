package com.ael.gatewayserver;

import com.ael.gatewayserver.filter.JwtAuthenticationFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.cloud.openfeign.EnableFeignClients;
import org.springframework.context.annotation.Bean;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsWebFilter;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;

import java.time.LocalDateTime;
import java.util.List;

@SpringBootApplication
@EnableDiscoveryClient
public class GatewayserverApplication {

	@Autowired
	private JwtAuthenticationFilter jwtAuthenticationFilter;

	public static void main(String[] args) {
		SpringApplication.run(GatewayserverApplication.class, args);
	}

	@Bean
	public RouteLocator greenProjectRouteConfig(RouteLocatorBuilder routeLocatorBuilder) {
		return routeLocatorBuilder.routes()
				.route(p -> p
						.path("/authservice/basicauth/**", "/authservice/google-auth/**")
						.filters(f -> f.rewritePath("/authservice/(?<segment>.*)","/${segment}")
								.addResponseHeader("X-Response-Time", LocalDateTime.now().toString())
						)
						.uri("lb://AUTHSERVICE"))
				.route(p -> p
						.path("/authservice/2fa/**")
						.filters(f -> f.rewritePath("/authservice/(?<segment>.*)","/${segment}")
								.addResponseHeader("X-Response-Time", LocalDateTime.now().toString())
								.filter(jwtAuthenticationFilter.apply(new JwtAuthenticationFilter.Config()))
						)
						.uri("lb://AUTHSERVICE"))
				.route(p -> p
						.path("/authservice/account/**")
						.filters(f -> f.rewritePath("/authservice/(?<segment>.*)","/${segment}")
								.addResponseHeader("X-Response-Time", LocalDateTime.now().toString())
								.filter(jwtAuthenticationFilter.apply(new JwtAuthenticationFilter.Config()))
						)
						.uri("lb://AUTHSERVICE"))
				.route(p -> p
						.path("/customerservice/**")
						.filters( f -> f.rewritePath("/ael/customerservice/(?<segment>.*)","/${segment}")
								.addResponseHeader("X-Response-Time", LocalDateTime.now().toString())
								.filter(jwtAuthenticationFilter.apply(new JwtAuthenticationFilter.Config()))
						)
						.uri("lb://CUSTOMERSERVICE"))
				.route(p -> p
						.path("/basketservice/basket/addProductToGuestBasket/**")
						.filters(f -> f.rewritePath("/ael/basketservice/(?<segment>.*)", "/${segment}")
								.addResponseHeader("X-Response-Time", LocalDateTime.now().toString()))
						.uri("lb://BASKETSERVICE"))
				.route(p -> p
						.path("/basketservice/basket/getGuestbasket/**")
						.filters(f -> f.rewritePath("/ael/basketservice/(?<segment>.*)", "/${segment}")
								.addResponseHeader("X-Response-Time", LocalDateTime.now().toString()))
						.uri("lb://BASKETSERVICE"))
				.route(p -> p
						.path("/basketservice/**")
						.filters( f -> f.rewritePath("/ael/basketservice/(?<segment>.*)","/${segment}")
								.addResponseHeader("X-Response-Time", LocalDateTime.now().toString())
								.filter(jwtAuthenticationFilter.apply(new JwtAuthenticationFilter.Config())))
						.uri("lb://BASKETSERVICE"))
				.route(p -> p
						.path("/paymentservice/payment/3ds/callback")
						.filters( f -> f.rewritePath("/ael/paymentservice/(?<segment>.*)","/${segment}")
								.addResponseHeader("X-Response-Time", LocalDateTime.now().toString())
								)
						.uri("lb://PAYMENTSERVICE"))
				.route(p -> p
						.path("/paymentservice/payment/3ds/Initialize")
						.filters( f -> f.rewritePath("/ael/paymentservice/(?<segment>.*)","/${segment}")
								.addResponseHeader("X-Response-Time", LocalDateTime.now().toString())
								.filter(jwtAuthenticationFilter.apply(new JwtAuthenticationFilter.Config())))
						.uri("lb://PAYMENTSERVICE"))
				.route(p -> p
						.path("/productservice/**")
						.filters( f -> f.rewritePath("/ael/productservice/(?<segment>.*)","/${segment}")
								.addResponseHeader("X-Response-Time", LocalDateTime.now().toString()))
						.uri("lb://PRODUCTSERVICE"))
				.route(p -> p
						.path("/orderservice/**")
						.filters( f -> f.rewritePath("/ael/orderservice/(?<segment>.*)","/${segment}")
								.addResponseHeader("X-Response-Time", LocalDateTime.now().toString())
								.filter(jwtAuthenticationFilter.apply(new JwtAuthenticationFilter.Config()))
						)
						.uri("lb://ORDERSERVICE"))
				.route(p -> p
						.path("/qr/**")
						.filters( f -> f
								.addResponseHeader("X-Response-Time", LocalDateTime.now().toString())
								.filter(jwtAuthenticationFilter.apply(new JwtAuthenticationFilter.Config()))
						)
						.uri("lb://ALGORYQR-SERVICE"))
				.build();

	}


}
