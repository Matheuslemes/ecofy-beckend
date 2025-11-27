package br.com.ecofy.auth.adapters.out.persistence.entity;

import br.com.ecofy.auth.core.domain.enums.TokenType;
import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "auth_refresh_tokens")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class RefreshTokenEntity {

    @Id
    @Column(name = "id", columnDefinition = "uuid")
    private UUID id;

    @Column(name = "token_value", unique = true, nullable = false, length = 2048)
    private String tokenValue;

    @Column(name = "user_id", columnDefinition = "uuid", nullable = false)
    private UUID userId;

    @Column(name = "client_id", nullable = false, length = 100)
    private String clientId;

    @Column(name = "issued_at", nullable = false)
    private Instant issuedAt;

    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;

    @Column(name = "revoked", nullable = false)
    private boolean revoked;

    @Enumerated(EnumType.STRING)
    @Column(
            name = "type",
            nullable = false,
            columnDefinition = "token_type" // enum do PostgreSQL
    )
    private TokenType type;
}
