package es.animal.hogar.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final JwtRequestFilter jwtRequestFilter;

    public SecurityConfig(JwtRequestFilter jwtRequestFilter) {
        this.jwtRequestFilter = jwtRequestFilter;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .csrf(AbstractHttpConfigurer::disable) // Desactivar CSRF porque no estamos usando sesiones
            .authorizeHttpRequests((authorize) -> authorize
            	.requestMatchers("/api/**").permitAll() // Permite acceso sin autenticación a rutas públicas
            	.requestMatchers("/v3/api-docs/**").permitAll()
            	.requestMatchers("/protected/api/**").authenticated() // Requiere autenticación para rutas protegidas
                .anyRequest().authenticated() // Requiere autenticación para cualquier otra solicitud 
            )
            .sessionManagement((session) -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS) // Indica que no se deben usar sesiones
            );

        // Añadir el filtro JWT antes del filtro de autenticación de Spring
        http.addFilterBefore(jwtRequestFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}
