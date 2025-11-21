package br.com.ecofy.auth.core.application.service;

import br.com.ecofy.auth.core.port.in.ValidateTokenUseCase;
import br.com.ecofy.auth.core.port.out.JwtTokenProviderPort;
import lombok.extern.slf4j.Slf4j;

import java.util.Map;
import java.util.Objects;

/**
 * Serviço responsável pela validação sintática e semântica de tokens JWT.
 *
 * Este serviço usa apenas validação passiva (assinatura + expiração),
 * delegando a lógica avançada para JwtTokenProviderPort.
 *
 * Pode ser futuramente estendido para:
 *  - introspecção ativa
 *  - blacklist / revogação baseada em jti
 *  - validações customizadas de claims
 */
@Slf4j
public class TokenValidationService implements ValidateTokenUseCase {

    private final JwtTokenProviderPort jwtTokenProviderPort;

    public TokenValidationService(JwtTokenProviderPort jwtTokenProviderPort) {
        this.jwtTokenProviderPort =
                Objects.requireNonNull(jwtTokenProviderPort, "jwtTokenProviderPort must not be null");
    }

    @Override
    public Map<String, Object> validate(String token) {
        Objects.requireNonNull(token, "token must not be null");

        String masked = maskToken(token);

        log.debug(
                "[TokenValidationService] - [validate] -> Validando token tokenMask={}",
                masked
        );

        boolean valid = jwtTokenProviderPort.isValid(token);

        if (!valid) {
            log.warn(
                    "[TokenValidationService] - [validate] -> Token inválido tokenMask={}",
                    masked
            );
            throw new IllegalArgumentException("Invalid token");
        }

        Map<String, Object> claims = jwtTokenProviderPort.parseClaims(token);

        log.debug(
                "[TokenValidationService] - [validate] -> Token válido, claims extraídas tokenMask={} claimsKeys={}",
                masked,
                claims.keySet()
        );

        return claims;
    }

    // Utils
    private String maskToken(String token) {
        if (token == null || token.isBlank()) return "***";
        return token.length() > 12 ? token.substring(0, 12) + "..." : "***";
    }
}
