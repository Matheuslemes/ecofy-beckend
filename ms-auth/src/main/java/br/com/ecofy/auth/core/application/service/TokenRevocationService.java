package br.com.ecofy.auth.core.application.service;

import br.com.ecofy.auth.core.port.in.RevokeTokenUseCase;
import br.com.ecofy.auth.core.port.out.RefreshTokenStorePort;
import lombok.extern.slf4j.Slf4j;

import java.util.Objects;

/**
 * Serviço responsável por revogar tokens emitidos pelo MS Auth.
 * Atualmente:
 *  - Revoga refresh tokens (persistidos em store especializado)
 *  - Pode ser estendido para suportar revogação de access tokens
 *    (lista de bloqueio, cache distribuído, Redis, etc).
 */
@Slf4j
public class TokenRevocationService implements RevokeTokenUseCase {

    private final RefreshTokenStorePort refreshTokenStorePort;

    public TokenRevocationService(RefreshTokenStorePort refreshTokenStorePort) {
        this.refreshTokenStorePort =
                Objects.requireNonNull(refreshTokenStorePort, "refreshTokenStorePort must not be null");
    }

    @Override
    public void revoke(RevokeTokenCommand command) {
        Objects.requireNonNull(command, "command must not be null");
        String masked = maskToken(command.token());

        log.debug(
                "[TokenRevocationService] - [revoke] -> Iniciando revogação de token={} isRefreshToken={}",
                masked, command.refreshToken()
        );

        if (command.refreshToken()) {
            refreshTokenStorePort.revoke(command.token());
            log.debug(
                    "[TokenRevocationService] - [revoke] -> Refresh token revogado tokenMask={}",
                    masked
            );
        }

        // FUTURO: se desejar implementar revogação de access token:
        // - adicionar AccessTokenBlacklistPort ou Cache
        // - armazenar jti ou tokenValue por TTL = expiração natural
        // - validar blacklist no JwtDecoder

        log.debug(
                "[TokenRevocationService] - [revoke] -> Processo concluído tokenMask={}",
                masked
        );
    }

    private String maskToken(String token) {
        if (token == null || token.isBlank()) return "***";
        return token.length() > 10 ? token.substring(0, 10) + "..." : "***";
    }
}
