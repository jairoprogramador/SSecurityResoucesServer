package com.jairoprogramador.ssecurity.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

    @Value("${server.authorization.url}")
    private String authorizationUrl;
    private static final String[] USER_RESOURCES = {"/loans/**","/balance/**"};
    private static final String[] ADMIN_RESOURCES = {"/accounts/**","/cards/**"};
    private static final String ROLE_ADMIN = "ADMIN";
    private static final String ROLE_USER = "USER";

    @Bean
    SecurityFilterChain userSecurityFilterChain(HttpSecurity httpSecurity) throws Exception{
        httpSecurity.formLogin(Customizer.withDefaults());
        httpSecurity.authorizeHttpRequests(auth -> auth
                .requestMatchers(ADMIN_RESOURCES).hasRole(ROLE_ADMIN)
                .requestMatchers(USER_RESOURCES).hasRole(ROLE_USER)
                .anyRequest().permitAll()
        );
        httpSecurity.oauth2ResourceServer(oauth -> oauth.jwt(
                jwtConfigurer -> jwtConfigurer.decoder(JwtDecoders.fromOidcIssuerLocation(authorizationUrl))
        ));
        return httpSecurity.build();
    }

    @Bean
    JwtAuthenticationConverter jwtAuthenticationConverter(){
        var authConverter = new JwtGrantedAuthoritiesConverter();
        authConverter.setAuthoritiesClaimName("roles");
        authConverter.setAuthorityPrefix("");

        var converterResponse = new JwtAuthenticationConverter();
        converterResponse.setJwtGrantedAuthoritiesConverter(authConverter);
        return  converterResponse;
    }

}
