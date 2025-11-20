package br.com.ecofy.auth.core.domain;


import br.com.ecofy.auth.core.domain.enums.TokenType;

import java.time.Instant;
import java.util.Objects;

public final class JwtToken {

    private final String value;

    private final Instant expiresAt;

    private final TokenType type;

    public JwtToken(String value, Instant expiresAt, TokenType type) {
        this.value = Objects.requireNonNull(value);
        this.expiresAt = Objects.requireNonNull(expiresAt);
        this.type = Objects.requireNonNull(type);
    }

    public String value() {
        return value;
    }

    public Instant expiresAt() {
        return expiresAt;
    }

    public TokenType type() {
        return type;
    }

    public boolean isExpired() {
        return Instant.now().isAfter(expiresAt);
    }

}