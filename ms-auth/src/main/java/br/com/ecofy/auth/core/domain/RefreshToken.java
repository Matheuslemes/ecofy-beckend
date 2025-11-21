package br.com.ecofy.auth.core.domain;

import br.com.ecofy.auth.core.domain.enums.TokenType;
import br.com.ecofy.auth.core.domain.valueobject.AuthUserId;

import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/**
 * Modelo de refresh token mantido no domínio (mesmo se ele for JWT).
 * <p>
 * O valor pode ser:
 * - opaco (random/UUID/token criptográfico)
 * - JWT assinado
 */
public class RefreshToken {

    /** Identificador interno do refresh token (UUID string). */
    private final String id;

    /** Valor do token entregue ao cliente (opaco ou JWT). */
    private final String tokenValue;

    /** Referência ao usuário dono do token. */
    private final AuthUserId userId;

    /** client_id do client OAuth/OIDC que recebeu o token. */
    private final String clientId;

    /** Instante de emissão do token. */
    private final Instant issuedAt;

    /** Instante de expiração do token. */
    private final Instant expiresAt;

    /** Flag de revogação (logout, rotate, comprometimento, etc.). */
    private boolean revoked;

    /** Tipo do token – aqui deve ser sempre REFRESH. */
    private final TokenType type;

    public RefreshToken(String id,
                        String tokenValue,
                        AuthUserId userId,
                        String clientId,
                        Instant issuedAt,
                        Instant expiresAt,
                        boolean revoked,
                        TokenType type) {

        this.id = Objects.requireNonNull(id, "id must not be null");
        this.tokenValue = normalizeTokenValue(tokenValue);
        this.userId = Objects.requireNonNull(userId, "userId must not be null");
        this.clientId = normalizeClientId(clientId);
        this.issuedAt = Objects.requireNonNull(issuedAt, "issuedAt must not be null");
        this.expiresAt = Objects.requireNonNull(expiresAt, "expiresAt must not be null");
        this.type = Objects.requireNonNull(type, "type must not be null");

        // Domínio mais explícito: este agregado representa refresh tokens.
        if (this.type != TokenType.REFRESH) {
            throw new IllegalArgumentException("RefreshToken.type must be REFRESH");
        }

        if (expiresAt.isBefore(issuedAt)) {
            throw new IllegalArgumentException("expiresAt must be greater than or equal to issuedAt");
        }

        this.revoked = revoked;
    }

    /**
     * Fábrica para criar um novo refresh token com TTL em segundos.
     */
    public static RefreshToken create(AuthUserId userId,
                                      String clientId,
                                      String tokenValue,
                                      long ttlSeconds) {

        if (ttlSeconds <= 0) {
            throw new IllegalArgumentException("ttlSeconds must be greater than zero");
        }

        Instant now = Instant.now();
        Instant exp = now.plusSeconds(ttlSeconds);

        return new RefreshToken(
                UUID.randomUUID().toString(),
                tokenValue,
                userId,
                clientId,
                now,
                exp,
                false,
                TokenType.REFRESH
        );
    }

    // Getters (imutáveis externamente)
    public String id() {
        return id;
    }

    public String tokenValue() {
        return tokenValue;
    }

    public AuthUserId userId() {
        return userId;
    }

    public String clientId() {
        return clientId;
    }

    public Instant issuedAt() {
        return issuedAt;
    }

    public Instant expiresAt() {
        return expiresAt;
    }

    public boolean isRevoked() {
        return revoked;
    }

    public TokenType type() {
        return type;
    }

    // Regras de domínio
    public boolean isExpired() {
        return Instant.now().isAfter(expiresAt);
    }

    public boolean isActive() {
        return !revoked && !isExpired();
    }

    public Duration timeToExpire() {
        return Duration.between(Instant.now(), expiresAt);
    }

    /**
     * Revoga o token. Operação idempotente.
     */
    public void revoke() {
        if (this.revoked) {
            return;
        }
        this.revoked = true;
    }

    // Internals
    private String normalizeTokenValue(String value) {
        Objects.requireNonNull(value, "tokenValue must not be null");
        String trimmed = value.trim();
        if (trimmed.isEmpty()) {
            throw new IllegalArgumentException("tokenValue must not be blank");
        }
        return trimmed;
    }

    private String normalizeClientId(String clientId) {
        Objects.requireNonNull(clientId, "clientId must not be null");
        String trimmed = clientId.trim();
        if (trimmed.isEmpty()) {
            throw new IllegalArgumentException("clientId must not be blank");
        }
        return trimmed;
    }

    // equals / hashCode / toString
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof RefreshToken that)) return false;
        // identidade por id interno
        return Objects.equals(id, that.id);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }

    /**
     * Não exibe o tokenValue completo para evitar vazamento em logs.
     */
    @Override
    public String toString() {
        String masked = tokenValue.length() > 12 ? tokenValue.substring(0, 12) + "..." : "***";
        return "RefreshToken{" +
                "id='" + id + '\'' +
                ", tokenValue='" + masked + '\'' +
                ", userId=" + userId.value() +
                ", clientId='" + clientId + '\'' +
                ", issuedAt=" + issuedAt +
                ", expiresAt=" + expiresAt +
                ", revoked=" + revoked +
                '}';
    }
}
