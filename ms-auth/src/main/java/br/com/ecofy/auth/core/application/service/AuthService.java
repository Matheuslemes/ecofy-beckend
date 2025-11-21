package br.com.ecofy.auth.core.application.service;

import br.com.ecofy.auth.core.domain.AuthUser;
import br.com.ecofy.auth.core.domain.ClientApplication;
import br.com.ecofy.auth.core.domain.JwtToken;
import br.com.ecofy.auth.core.domain.RefreshToken;
import br.com.ecofy.auth.core.domain.enums.ClientType;
import br.com.ecofy.auth.core.domain.enums.GrantType;
import br.com.ecofy.auth.core.domain.enums.TokenType;
import br.com.ecofy.auth.core.domain.event.UserAuthenticatedEvent;
import br.com.ecofy.auth.core.domain.valueobject.EmailAddress;
import br.com.ecofy.auth.core.port.in.AuthenticateUserUseCase;
import br.com.ecofy.auth.core.port.in.RefreshTokenUseCase;
import br.com.ecofy.auth.core.port.out.*;
import lombok.extern.slf4j.Slf4j;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

@Slf4j
public class AuthService implements AuthenticateUserUseCase, RefreshTokenUseCase {

    private final LoadAuthUserByEmailPort loadAuthUserByEmailPort;
    private final LoadClientApplicationByClientIdPort loadClientApplicationByClientIdPort;
    private final PasswordHashingPort passwordHashingPort;
    private final JwtTokenProviderPort jwtTokenProviderPort;
    private final RefreshTokenStorePort refreshTokenStorePort;
    private final PublishAuthEventPort publishAuthEventPort;

    private final long accessTokenTtlSeconds;
    private final long refreshTokenTtlSeconds;

    public AuthService(LoadAuthUserByEmailPort loadAuthUserByEmailPort,
                       LoadClientApplicationByClientIdPort loadClientApplicationByClientIdPort,
                       PasswordHashingPort passwordHashingPort,
                       JwtTokenProviderPort jwtTokenProviderPort,
                       RefreshTokenStorePort refreshTokenStorePort,
                       PublishAuthEventPort publishAuthEventPort,
                       long accessTokenTtlSeconds,
                       long refreshTokenTtlSeconds) {

        this.loadAuthUserByEmailPort =
                Objects.requireNonNull(loadAuthUserByEmailPort, "loadAuthUserByEmailPort must not be null");
        this.loadClientApplicationByClientIdPort =
                Objects.requireNonNull(loadClientApplicationByClientIdPort, "loadClientApplicationByClientIdPort must not be null");
        this.passwordHashingPort =
                Objects.requireNonNull(passwordHashingPort, "passwordHashingPort must not be null");
        this.jwtTokenProviderPort =
                Objects.requireNonNull(jwtTokenProviderPort, "jwtTokenProviderPort must not be null");
        this.refreshTokenStorePort =
                Objects.requireNonNull(refreshTokenStorePort, "refreshTokenStorePort must not be null");
        this.publishAuthEventPort =
                Objects.requireNonNull(publishAuthEventPort, "publishAuthEventPort must not be null");

        this.accessTokenTtlSeconds = accessTokenTtlSeconds;
        this.refreshTokenTtlSeconds = refreshTokenTtlSeconds;
    }

    // PASSWORD GRANT (username/password)
    @Override
    public AuthenticationResult authenticate(AuthenticationCommand command) {
        Objects.requireNonNull(command, "command must not be null");

        log.debug(
                "[AuthService] - [authenticate] -> Iniciando autenticação clientId={} username={} scope={}",
                command.clientId(), command.username(), command.scope()
        );

        ClientApplication client = loadClientApplicationByClientIdPort
                .loadByClientId(command.clientId())
                .orElseThrow(() -> {
                    log.warn(
                            "[AuthService] - [authenticate] -> client_id inválido clientId={}",
                            command.clientId()
                    );
                    return new IllegalArgumentException("Invalid client_id");
                });

        validateClientForPasswordGrant(client);

        AuthUser user = loadAuthUserByEmailPort
                .loadByEmail(new EmailAddress(command.username()))
                .orElseThrow(() -> {
                    log.warn(
                            "[AuthService] - [authenticate] -> Credenciais inválidas (usuário não encontrado) username={}",
                            command.username()
                    );
                    return new IllegalArgumentException("Invalid credentials");
                });

        if (!passwordHashingPort.matches(command.password(), user.passwordHash())) {
            user.registerFailedLogin(5); // política de lock no domínio
            log.warn(
                    "[AuthService] - [authenticate] -> Senha inválida username={} failedAttempts={}",
                    command.username(), user.failedLoginAttempts()
            );
            throw new IllegalArgumentException("Invalid credentials");
        }

        user.registerSuccessfulLogin();

        Map<String, Object> accessClaims = buildAccessTokenClaims(user, client, command.scope());
        JwtToken accessToken = jwtTokenProviderPort
                .generateAccessToken(user.id().value().toString(), accessClaims, accessTokenTtlSeconds);

        Map<String, Object> refreshClaims = buildRefreshTokenClaims(user, client);
        JwtToken refreshJwt = jwtTokenProviderPort
                .generateRefreshToken(user.id().value().toString(), refreshClaims, refreshTokenTtlSeconds);

        RefreshToken refreshToken = RefreshToken.create(
                user.id(),
                client.clientId(),
                refreshJwt.value(),
                refreshTokenTtlSeconds
        );
        refreshTokenStorePort.save(refreshToken);

        publishAuthEventPort.publish(
                new UserAuthenticatedEvent(user, client, command.ipAddress())
        );

        log.debug(
                "[AuthService] - [authenticate] -> Autenticação bem sucedida userId={} clientId={}",
                user.id().value(), client.clientId()
        );

        return new AuthenticationResult(
                accessToken,
                refreshJwt.value(),
                accessTokenTtlSeconds,
                "Bearer"
        );
    }

    // REFRESH TOKEN GRANT
    @Override
    public RefreshTokenResult refresh(RefreshTokenCommand command) {
        Objects.requireNonNull(command, "command must not be null");

        String maskedToken = maskToken(command.refreshToken());
        log.debug(
                "[AuthService] - [refresh] -> Iniciando fluxo de refresh clientId={} tokenMask={}",
                command.clientId(), maskedToken
        );

        RefreshToken stored = refreshTokenStorePort
                .findByTokenValue(command.refreshToken())
                .orElseThrow(() -> {
                    log.warn(
                            "[AuthService] - [refresh] -> Refresh token não encontrado tokenMask={}",
                            maskedToken
                    );
                    return new IllegalArgumentException("Invalid refresh token");
                });

        if (!stored.isActive()) {
            log.warn(
                    "[AuthService] - [refresh] -> Refresh token expirado ou revogado tokenMask={}",
                    maskedToken
            );
            throw new IllegalArgumentException("Refresh token expired or revoked");
        }

        Map<String, Object> claims = jwtTokenProviderPort.parseClaims(stored.tokenValue());

        // Usa o claim "typ" com enum TokenType (novos enums sendo usados aqui)
        Object rawType = claims.get("typ");
        if (rawType == null || !TokenType.REFRESH.name().equals(rawType.toString())) {
            log.warn(
                    "[AuthService] - [refresh] -> Token de tipo inválido para fluxo de refresh typ={} tokenMask={}",
                    rawType, maskedToken
            );
            throw new IllegalArgumentException("Invalid token type for refresh flow");
        }

        String userId = (String) claims.get("sub");
        String clientIdFromClaims = (String) claims.get("client_id");

        if (userId == null || clientIdFromClaims == null) {
            log.warn(
                    "[AuthService] - [refresh] -> Claims de refresh token malformadas tokenMask={}",
                    maskedToken
            );
            throw new IllegalArgumentException("Malformed refresh token claims");
        }

        // valida client_id do comando x token salvo x claims
        if (!stored.clientId().equals(command.clientId()) || !clientIdFromClaims.equals(command.clientId())) {
            log.warn(
                    "[AuthService] - [refresh] -> Refresh token não pertence ao client armazenadoClientId={} claimsClientId={} commandClientId={} tokenMask={}",
                    stored.clientId(), clientIdFromClaims, command.clientId(), maskedToken
            );
            throw new IllegalArgumentException("Refresh token does not belong to client");
        }

        // garante que o client ainda é válido e suporta REFRESH_TOKEN
        ClientApplication client = loadClientApplicationByClientIdPort
                .loadByClientId(command.clientId())
                .orElseThrow(() -> {
                    log.warn(
                            "[AuthService] - [refresh] -> Client não encontrado para fluxo de refresh clientId={}",
                            command.clientId()
                    );
                    return new IllegalArgumentException("Client not found for refresh flow");
                });

        validateClientForRefreshGrant(client);

        // Gera novo access token reaproveitando (ou refinando) os claims
        JwtToken newAccess = jwtTokenProviderPort
                .generateAccessToken(userId, claims, accessTokenTtlSeconds);

        // Novo refresh token com claims mínimos e tipagem REFRESH tratada no provider
        Map<String, Object> refreshClaims = Map.of("client_id", clientIdFromClaims);
        JwtToken newRefresh = jwtTokenProviderPort
                .generateRefreshToken(userId, refreshClaims, refreshTokenTtlSeconds);

        RefreshToken newStored = RefreshToken.create(
                stored.userId(),
                stored.clientId(),
                newRefresh.value(),
                refreshTokenTtlSeconds
        );

        refreshTokenStorePort.save(newStored);
        refreshTokenStorePort.revoke(stored.tokenValue());

        log.debug(
                "[AuthService] - [refresh] -> Refresh concluído com sucesso userId={} clientId={}",
                stored.userId().value(), stored.clientId()
        );

        return new RefreshTokenResult(
                newAccess.value(),
                newRefresh.value(),
                accessTokenTtlSeconds
        );
    }

    // Helpers de domínio / regras de grant
    /**
     * Regras para PASSWORD grant:
     *  - client deve estar ativo
     *  - deve suportar GrantType.PASSWORD
     *  - tipo do client deve ser compatível (CONFIDENTIAL ou SPA, por ex.)
     */
    private void validateClientForPasswordGrant(ClientApplication client) {
        if (!client.isActive()) {
            log.warn(
                    "[AuthService] - [validateClientForPasswordGrant] -> Client inativo clientId={}",
                    client.clientId()
            );
            throw new IllegalArgumentException("Client is inactive");
        }

        if (!client.supportsGrant(GrantType.PASSWORD)) {
            log.warn(
                    "[AuthService] - [validateClientForPasswordGrant] -> Client não suporta PASSWORD grant clientId={}",
                    client.clientId()
            );
            throw new IllegalArgumentException("Client does not support PASSWORD grant");
        }

        ClientType type = client.clientType();
        if (type != ClientType.CONFIDENTIAL && type != ClientType.SPA) {
            log.warn(
                    "[AuthService] - [validateClientForPasswordGrant] -> Tipo de client não permitido para PASSWORD grant clientId={} type={}",
                    client.clientId(), type
            );
            throw new IllegalArgumentException("Client type not allowed for PASSWORD grant");
        }
    }

    /**
     * Regras para REFRESH_TOKEN grant:
     *  - client ativo
     *  - suporta REFRESH_TOKEN
     */
    private void validateClientForRefreshGrant(ClientApplication client) {
        if (!client.isActive()) {
            log.warn(
                    "[AuthService] - [validateClientForRefreshGrant] -> Client inativo clientId={}",
                    client.clientId()
            );
            throw new IllegalArgumentException("Client is inactive");
        }

        if (!client.supportsGrant(GrantType.REFRESH_TOKEN)) {
            log.warn(
                    "[AuthService] - [validateClientForRefreshGrant] -> Client não suporta REFRESH_TOKEN grant clientId={}",
                    client.clientId()
            );
            throw new IllegalArgumentException("Client does not support REFRESH_TOKEN grant");
        }
    }

    private Map<String, Object> buildAccessTokenClaims(AuthUser user,
                                                       ClientApplication client,
                                                       String scope) {

        Map<String, Object> claims = new HashMap<>();
        claims.put("sub", user.id().value().toString());
        claims.put("email", user.email().value());
        claims.put("name", user.fullName());
        claims.put("client_id", client.clientId());

        if (scope != null && !scope.isBlank()) {
            claims.put("scope", scope);
        }

        // Futuro: roles / permissions
        // claims.put("roles", ...);
        // claims.put("permissions", ...);

        return claims;
    }

    private Map<String, Object> buildRefreshTokenClaims(AuthUser user,
                                                        ClientApplication client) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("sub", user.id().value().toString());
        claims.put("client_id", client.clientId());
        return claims;
    }

    private String maskToken(String token) {
        if (token == null || token.isBlank()) {
            return "***";
        }
        return token.length() > 12 ? token.substring(0, 12) + "..." : "***";
    }
}
