package br.com.ecofy.auth.core.domain;

import br.com.ecofy.auth.core.domain.enums.TokenType;

import java.time.Duration;
import java.time.Instant;
import java.util.Objects;

/**
 * Value object que representa um JWT emitido pelo ms-auth.
 * Imutável, sem comportamento criptográfico – apenas metadados.
 */
public final class JwtToken {

    /** Valor serializado do JWT (header.payload.signature). */
    private final String value;

    /** Instante exato em que o token expira. */
    private final Instant expiresAt;

    /** Tipo do token: ACCESS / REFRESH. */
    private final TokenType type;

    public JwtToken(String value, Instant expiresAt, TokenType type) {
        this.value = normalizeToken(value);
        this.expiresAt = Objects.requireNonNull(expiresAt, "expiresAt must not be null");
        this.type = Objects.requireNonNull(type, "type must not be null");

        if (expiresAt.isBefore(Instant.now().minusSeconds(5))) {
            // proteção contra tokens criados "expirados"
            throw new IllegalArgumentException("expiresAt cannot be in the past");
        }
    }

    // Normalização
    private String normalizeToken(String raw) {
        Objects.requireNonNull(raw, "value must not be null");
        String token = raw.trim();
        if (token.isEmpty()) {
            throw new IllegalArgumentException("JWT value must not be blank");
        }
        return token;
    }

    // Getters imutáveis
    public String value() {
        return value;
    }

    public Instant expiresAt() {
        return expiresAt;
    }

    public TokenType type() {
        return type;
    }

    // Métodos utilitários de domínio
    public boolean isExpired() {
        return Instant.now().isAfter(expiresAt);
    }

    public boolean isActive() {
        return !isExpired();
    }

    /**
     * Tempo restante até expirar.
     */
    public Duration timeToExpire() {
        return Duration.between(Instant.now(), expiresAt);
    }

    /**
     * Útil para fluxos de rotated refresh tokens / silent refresh.
     * Ex.: considerar "prestes a expirar" se faltam menos que N segundos.
     */
    public boolean isAboutToExpire(Duration threshold) {
        Objects.requireNonNull(threshold, "threshold must not be null");
        return !isExpired() && timeToExpire().compareTo(threshold) <= 0;
    }

    // equals, hashCode e toString seguro
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof JwtToken that)) return false;
        return Objects.equals(value, that.value);
    }

    @Override
    public int hashCode() {
        return Objects.hash(value);
    }

    /**
     * Nunca imprime o token completo para evitar vazamento de credenciais.
     * Mostra apenas os 12 primeiros caracteres e "...".
     */
    @Override
    public String toString() {
        String masked = value.length() > 12 ? value.substring(0, 12) + "..." : "***";
        return "JwtToken{" +
                "value='" + masked + '\'' +
                ", expiresAt=" + expiresAt +
                ", type=" + type +
                '}';
    }
}
