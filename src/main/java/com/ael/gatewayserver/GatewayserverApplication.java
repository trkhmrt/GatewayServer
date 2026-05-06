package com.ael.gatewayserver;

import com.ael.gatewayserver.filter.JwtAuthenticationFilter;
import org.springframework.boot.SpringApplication;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpMethod;

import java.time.LocalDateTime;

@SpringBootApplication
public class GatewayserverApplication {
	private final JwtAuthenticationFilter jwtAuthenticationFilter;
	private final String authServiceUri;
	private final String qrServiceUri;
	private final String rentServiceUri;

	public GatewayserverApplication(
			JwtAuthenticationFilter jwtAuthenticationFilter,
			@Value("${app.services.auth.uri:http://authservice:8080}") String authServiceUri,
			@Value("${app.services.qr.uri:http://algoryqr-service:8080}") String qrServiceUri,
			@Value("${app.services.rent.uri:http://algorycode-rent-service:8090}") String rentServiceUri
	) {
		this.jwtAuthenticationFilter = jwtAuthenticationFilter;
		this.authServiceUri = authServiceUri;
		this.qrServiceUri = qrServiceUri;
		this.rentServiceUri = rentServiceUri;
	}

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
						.uri(authServiceUri))
				.route(p -> p
						.path("/authservice/2fa/**")
						.filters(f -> f.rewritePath("/authservice/(?<segment>.*)","/${segment}")
								.addResponseHeader("X-Response-Time", LocalDateTime.now().toString())
								.filter(jwtAuthenticationFilter.apply(new JwtAuthenticationFilter.Config()))
						)
						.uri(authServiceUri))
				.route(p -> p
						.path("/authservice/account/**")
						.filters(f -> f.rewritePath("/authservice/(?<segment>.*)","/${segment}")
								.addResponseHeader("X-Response-Time", LocalDateTime.now().toString())
								.filter(jwtAuthenticationFilter.apply(new JwtAuthenticationFilter.Config()))
						)
						.uri(authServiceUri))
				.route(p -> p
						.path("/authservice/admin/**")
						.filters(f -> f.rewritePath("/authservice/(?<segment>.*)", "/${segment}")
								.addResponseHeader("X-Response-Time", LocalDateTime.now().toString())
								.filter(jwtAuthenticationFilter.apply(new JwtAuthenticationFilter.Config()))
						)
						.uri(authServiceUri))
				.route(p -> p
						.path("/qr/**")
						.filters( f -> f
								.addResponseHeader("X-Response-Time", LocalDateTime.now().toString())
								.filter(jwtAuthenticationFilter.apply(new JwtAuthenticationFilter.Config()))
						)
						.uri(qrServiceUri))
				.route(p -> p
						.path("/rent/guest/**")
						.filters(f -> f.rewritePath("/rent/guest/(?<segment>.*)", "/${segment}")
								.addResponseHeader("X-Response-Time", LocalDateTime.now().toString())
						)
						.uri(rentServiceUri))
				/** Kiralama vitrin: liste ve tekil okuma JWT istemez (yalnızca GET). */
				.route(p -> p
						.path("/rent/vehicles")
						.and()
						.method(HttpMethod.GET)
						.filters(f -> f.rewritePath("/rent/vehicles", "/vehicles")
								.addResponseHeader("X-Response-Time", LocalDateTime.now().toString())
						)
						.uri(rentServiceUri))
				.route(p -> p
						.path("/rent/vehicles/*")
						.and()
						.method(HttpMethod.GET)
						.filters(f -> f.rewritePath("/rent/(?<segment>.*)", "/${segment}")
								.addResponseHeader("X-Response-Time", LocalDateTime.now().toString())
						)
						.uri(rentServiceUri))
				/** Vitrin alış/teslim noktaları: GET JWT istemez (misafir / anonim FE). */
				.route(p -> p
						.path("/rent/handover-locations")
						.and()
						.method(HttpMethod.GET)
						.filters(f -> f.rewritePath("/rent/handover-locations", "/handover-locations")
								.addResponseHeader("X-Response-Time", LocalDateTime.now().toString())
						)
						.uri(rentServiceUri))
				.route(p -> p
						.path("/rent/vehicle-statuses", "/rent/vehicle-statuses/**")
						.filters(f -> f
								.addResponseHeader("X-Response-Time", LocalDateTime.now().toString())
								.filter(jwtAuthenticationFilter.apply(new JwtAuthenticationFilter.Config()))
						)
						.uri(rentServiceUri))
				.route(p -> p
						.path("/rent/**")
						.filters(f -> f.rewritePath("/rent/(?<segment>.*)", "/${segment}")
								.addResponseHeader("X-Response-Time", LocalDateTime.now().toString())
								.filter(jwtAuthenticationFilter.apply(new JwtAuthenticationFilter.Config()))
						)
						.uri(rentServiceUri))
				.build();

	}


}
