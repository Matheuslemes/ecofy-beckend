package br.com.ecofy.auth.core.domain;

import java.time.Instant;
import java.util.Locale;
import java.util.Objects;

/**
 * Representação de uma chave pública exposta via JWKS no domínio.
 * Importante: aqui não há detalhes de implementação criptográfica, apenas
 * metadados necessários para publicação e rotação de chaves.
 */
public class JwkKey {

    public static final String USE_SIGNING    = "sig";
    public static final String USE_ENCRYPTION = "enc";

    private final String keyId;
    private final String publicKeyPem;
    private final String algorithm; // ex.: "RS256"
    private final String use; // "sig" ou "enc"
    private final Instant createdAt;
    private final boolean active;

    public JwkKey(String keyId,
                  String publicKeyPem,
                  String algorithm,
                  String use,
                  Instant createdAt,
                  boolean active) {

        this.keyId = Objects.requireNonNull(keyId, "keyId must not be null");
        this.publicKeyPem = Objects.requireNonNull(publicKeyPem, "publicKeyPem must not be null");
        this.algorithm = normalizeAlgorithm(algorithm);
        this.use = normalizeUse(use);
        this.createdAt = Objects.requireNonNull(createdAt, "createdAt must not be null");
        this.active = active;
    }

    // Getters
    public String keyId() {
        return keyId;
    }

    public String publicKeyPem() {
        return publicKeyPem;
    }

    public String algorithm() {
        return algorithm;
    }

    public String use() {
        return use;
    }

    public Instant createdAt() {
        return createdAt;
    }

    public boolean active() {
        return active;
    }

    // Helpers de domínio

    /**
     * Indica se a chave é usada para assinatura de tokens ("sig").
     */
    public boolean isSigningKey() {
        return USE_SIGNING.equalsIgnoreCase(use);
    }

    /**
     * Indica se a chave é usada para criptografia ("enc").
     */
    public boolean isEncryptionKey() {
        return USE_ENCRYPTION.equalsIgnoreCase(use);
    }

    // Internals
    private String normalizeAlgorithm(String algorithm) {
        Objects.requireNonNull(algorithm, "algorithm must not be null");
        String trimmed = algorithm.trim();
        if (trimmed.isEmpty()) {
            throw new IllegalArgumentException("algorithm must not be blank");
        }
        // Convenção: algoritmos em maiúsculas (RS256, ES256, etc.)
        return trimmed.toUpperCase(Locale.ROOT);
    }

    private String normalizeUse(String use) {
        if (use == null || use.isBlank()) {
            // default seguro: assinatura de tokens
            return USE_SIGNING;
        }
        String normalized = use.trim().toLowerCase(Locale.ROOT);
        if (!USE_SIGNING.equals(normalized) && !USE_ENCRYPTION.equals(normalized)) {
            throw new IllegalArgumentException("Invalid JWK use: " + use + ". Expected 'sig' or 'enc'.");
        }
        return normalized;
    }

    // equals / hashCode / toString
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof JwkKey jwkKey)) return false;
        // keyId é único no contexto de JWKS, suficiente para igualdade
        return Objects.equals(keyId, jwkKey.keyId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(keyId);
    }

    @Override
    public String toString() {
        return "JwkKey{" +
                "keyId='" + keyId + '\'' +
                ", algorithm='" + algorithm + '\'' +
                ", use='" + use + '\'' +
                ", active=" + active +
                ", createdAt=" + createdAt +
                '}';
    }
}
