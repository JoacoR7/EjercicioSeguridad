package com.is.biblioteca;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import com.is.biblioteca.business.logic.service.UsuarioService;

import static org.springframework.security.config.Customizer.withDefaults;

import org.springframework.beans.factory.annotation.Autowired;

@Configuration
@EnableMethodSecurity
public class WebSecurity {

	@Autowired
	UsuarioService usuarioService;
	
	@Autowired
	public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception{
		auth.userDetailsService(usuarioService)
				.passwordEncoder(new BCryptPasswordEncoder());
	}
	
	@Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            // Configuración de las autorizaciones para los endpoints
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/usuario/login", "/public/**").permitAll()  // Permitir acceso sin autenticación
                .anyRequest().authenticated()  // Proteger todos los demás endpoints
            )
            // Habilitar el login basado en formularios
            .formLogin(form -> form
                .loginPage("/usuario/login")  // Página de login personalizada
                .defaultSuccessUrl("/home", true)  // Redirección después del login
                .permitAll()  // Permitir acceso a la página de login sin autenticación
            )
            // Configuración del logout
            .logout(logout -> logout
                .logoutUrl("/logout")  // URL para cerrar sesión
                .logoutSuccessUrl("/login")  // Redirige después del logout
                .permitAll()
            )
            // Protección CSRF habilitada (opcionalmente la puedes deshabilitar si no es necesaria)
            .csrf(csrf -> csrf.disable());  // Deshabilitar CSRF (si realmente no lo necesitas)

        return http.build();
    }

}
