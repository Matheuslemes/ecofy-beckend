package br.com.ecofy.auth.core.domain;

import java.time.Instant;
import java.util.Objects;

// representacao de uma chave jwks no dominio (sem detalhes de implementacao)
public class JwkKey {

    private final String keyId;
    private final String publicKeyPem;
    private final String algorithm; // ex.: RS256
    private final String use; // "sig" ou "enc"
    private final Instant createdAt;
    private final boolean active;

    public JwkKey(String keyId,
                  String publicKeyPem,
                  String algorithm,
                  String use,
                  Instant createdAt,
                  boolean active) {
        this.keyId = Objects.requireNonNull(keyId);
        this.publicKeyPem = Objects.requireNonNull(publicKeyPem);
        this.algorithm = Objects.requireNonNull(algorithm);
        this.use = use != null ? use : "sig";
        this.createdAt = Objects.requireNonNull(createdAt);
        this.active = active;
    }

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

}
