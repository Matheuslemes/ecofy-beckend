package br.com.ecofy.auth.core.domain;

import br.com.ecofy.auth.core.domain.enums.TokenType;
import br.com.ecofy.auth.core.domain.valueobject.AuthUserId;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

// modelo de reflesh token mentido no dominio (mesmo se ele for JWT).
public class RefreshToken {

    private final String id;

    private final String tokenValue; // opaque ou JWT

    private final AuthUserId userId;

    private final String clientId;

    private final Instant issuedAt;

    private final Instant expiresAt;

    private boolean revoked;

    private final TokenType type;

    public RefreshToken(String id,
                        String tokenValue,
                        AuthUserId userId,
                        String clientId,
                        Instant issuedAt,
                        Instant expiresAt,
                        boolean revoked,
                        TokenType type) {
        this.id = Objects.requireNonNull(id);
        this.tokenValue = Objects.requireNonNull(tokenValue);
        this.userId = Objects.requireNonNull(userId);
        this.clientId = Objects.requireNonNull(clientId);
        this.issuedAt = Objects.requireNonNull(issuedAt);
        this.expiresAt = Objects.requireNonNull(expiresAt);
        this.revoked = revoked;
        this.type = Objects.requireNonNull(type);
    }

    public static RefreshToken create(AuthUserId userId,
                                      String clientId,
                                      String tokenValue,
                                      long ttlSeconds) {
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

    public boolean isExpired() {
        return Instant.now().isAfter(expiresAt);
    }

    public void revoke() {
        this.revoked = true;
    }

}
