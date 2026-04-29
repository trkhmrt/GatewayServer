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
import org.springframework.http.HttpMethod;

import java.time.LocalDateTime;

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
						.path("/authservice/admin/**")
						.filters(f -> f.rewritePath("/authservice/(?<segment>.*)", "/${segment}")
								.addResponseHeader("X-Response-Time", LocalDateTime.now().toString())
								.filter(jwtAuthenticationFilter.apply(new JwtAuthenticationFilter.Config()))
						)
						.uri("lb://AUTHSERVICE"))
				.route(p -> p
						.path("/qr/**")
						.filters( f -> f
								.addResponseHeader("X-Response-Time", LocalDateTime.now().toString())
								.filter(jwtAuthenticationFilter.apply(new JwtAuthenticationFilter.Config()))
						)
						.uri("lb://ALGORYQR-SERVICE"))
				.route(p -> p
						.path("/rent/guest/**")
						.filters(f -> f.rewritePath("/rent/guest/(?<segment>.*)", "/${segment}")
								.addResponseHeader("X-Response-Time", LocalDateTime.now().toString())
						)
						.uri("lb://ALGORYCODE-RENT-SERVICE"))
				/** Kiralama vitrin: liste ve tekil okuma JWT istemez (yalnızca GET). */
				.route(p -> p
						.path("/rent/vehicles")
						.and()
						.method(HttpMethod.GET)
						.filters(f -> f.rewritePath("/rent/vehicles", "/vehicles")
								.addResponseHeader("X-Response-Time", LocalDateTime.now().toString())
						)
						.uri("lb://ALGORYCODE-RENT-SERVICE"))
				.route(p -> p
						.path("/rent/vehicles/*")
						.and()
						.method(HttpMethod.GET)
						.filters(f -> f.rewritePath("/rent/(?<segment>.*)", "/${segment}")
								.addResponseHeader("X-Response-Time", LocalDateTime.now().toString())
						)
						.uri("lb://ALGORYCODE-RENT-SERVICE"))
				/** Vitrin alış/teslim noktaları: GET JWT istemez (misafir / anonim FE). */
				.route(p -> p
						.path("/rent/handover-locations")
						.and()
						.method(HttpMethod.GET)
						.filters(f -> f.rewritePath("/rent/handover-locations", "/handover-locations")
								.addResponseHeader("X-Response-Time", LocalDateTime.now().toString())
						)
						.uri("lb://ALGORYCODE-RENT-SERVICE"))
				.route(p -> p
						.path("/rent/vehicle-statuses", "/rent/vehicle-statuses/**")
						.filters(f -> f
								.addResponseHeader("X-Response-Time", LocalDateTime.now().toString())
								.filter(jwtAuthenticationFilter.apply(new JwtAuthenticationFilter.Config()))
						)
						.uri("lb://ALGORYCODE-RENT-SERVICE"))
				.route(p -> p
						.path("/rent/**")
						.filters(f -> f.rewritePath("/rent/(?<segment>.*)", "/${segment}")
								.addResponseHeader("X-Response-Time", LocalDateTime.now().toString())
								.filter(jwtAuthenticationFilter.apply(new JwtAuthenticationFilter.Config()))
						)
						.uri("lb://ALGORYCODE-RENT-SERVICE"))
				.build();

	}


}
