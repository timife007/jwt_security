package com.timife.jwt_security.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

//We need to bind all the security process.
//SpringBoot looks for a security filter bean at the start of the app, which is responsible for
//configuring all the http security of the application.
@Configuration
@RequiredArgsConstructor
public class SecurityConfig {

    //automatically injected by spring since they're in the same context, it's fine
    //even if I don't use autowired annotation to inject it, its @Component annot. is fine.
    private final JwtAuthenticationFilter jwtAuthFilter;
    private final AuthenticationProvider authenticationProvider;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity security) throws Exception {
        security
                .csrf()
                .disable()
                .authorizeHttpRequests()
                .requestMatchers("/api/v1/auth/**")  ///White listing, no need for authorization for requests like login.
                .permitAll()
                .anyRequest()
                .authenticated()
                .and()  //since we're using OncePerRequestFilter, it means the auth state or session state should not be stored i.e stateless.
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .authenticationProvider(authenticationProvider)
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);

        return security.build(); //an exception should be added to the configuration because it might throw an exception.
    }


}
