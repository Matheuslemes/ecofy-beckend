package br.com.ecofy.auth.config;

import br.com.ecofy.auth.adapters.out.jwt.JwtNimbusTokenProviderAdapter;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.RSAKey;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.web.SecurityFilterChain;

import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;

@Configuration
@EnableMethodSecurity
@EnableConfigurationProperties(JwtProperties.class)
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtProperties jwtProperties;
    private final JwtNimbusTokenProviderAdapter jwtNimbusTokenProviderAdapter;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12);
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, JwtDecoder jwtDecoder) throws Exception {

        http
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(auth -> auth
                        // Endpoints públicos
                        .requestMatchers(
                                "/actuator/health",
                                "/actuator/info",
                                "/v3/api-docs/**",
                                "/swagger-ui/**",
                                "/swagger-ui.html",
                                "/api/auth/token",
                                "/api/auth/refresh",
                                "/api/register/**",
                                "/api/password/**",
                                "/.well-known/jwks.json"
                        ).permitAll()
                        // permissão temporaria
//                        .requestMatchers("/api/admin/users").permitAll()
                        .requestMatchers("/api/admin/**").hasAuthority("AUTH_ADMIN")
                        .anyRequest().authenticated()
                )
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(jwt -> jwt.decoder(jwtDecoder))
                );

        // headers extras, HSTS, etc.
        http.headers(headers -> headers
                .contentSecurityPolicy(csp -> csp
                        .policyDirectives("default-src 'self'"))
                .frameOptions(frame -> frame.sameOrigin())
        );

        return http.build();
    }

    /**
     * JwtDecoder baseado na MESMA chave pública usada pelo JwtNimbusTokenProviderAdapter.
     * Em modo dev, a chave é gerada em memória no adapter.
     */
    @Bean
    public JwtDecoder jwtDecoder() {
        try {
            RSAKey rsaJwk = jwtNimbusTokenProviderAdapter.toRsaJwk();
            RSAPublicKey publicKey = rsaJwk.toRSAPublicKey();

            NimbusJwtDecoder decoder = NimbusJwtDecoder.withPublicKey(publicKey).build();
            decoder.setJwtValidator(new JwtValidatorFactory(jwtProperties).create());
            return decoder;

        } catch (JOSEException e) {

            throw new IllegalStateException("Could not create JwtDecoder from in-memory JWK", e);
        }
    }

    // fabrica simples para montar um validator customizado de JWT
    static class JwtValidatorFactory {

        private final JwtProperties jwtProperties;

        JwtValidatorFactory(JwtProperties jwtProperties) {
            this.jwtProperties = jwtProperties;
        }

        public OAuth2TokenValidator<Jwt> create() {

            var validators = new ArrayList<OAuth2TokenValidator<Jwt>>();

            if (jwtProperties.getIssuer() != null) {
                validators.add(new JwtIssuerValidator(jwtProperties.getIssuer()));
            }

            // validador default (timestamps, exp, nbf etc.)
            validators.add(JwtValidators.createDefault());

            return new DelegatingOAuth2TokenValidator<>(validators);

        }

    }

}
