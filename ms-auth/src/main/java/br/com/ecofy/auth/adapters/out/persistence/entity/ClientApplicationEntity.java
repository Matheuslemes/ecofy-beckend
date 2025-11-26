package br.com.ecofy.auth.adapters.out.persistence.entity;

import br.com.ecofy.auth.core.domain.enums.ClientType;
import br.com.ecofy.auth.core.domain.enums.GrantType;
import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;
import java.util.Set;

@Entity
@Table(name = "auth_client_applications")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ClientApplicationEntity {

    @Id
    @Column(name = "id", length = 36)
    private String id;

    @Column(name = "client_id", unique = true, nullable = false, length = 100)
    private String clientId;

    @Column(name = "client_secret_hash", length = 255)
    private String clientSecretHash;

    @Column(name = "name", nullable = false, length = 120)
    private String name;

    @Enumerated(EnumType.STRING)
    @Column(name = "client_type", nullable = false, length = 32)
    private ClientType clientType;

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(
            name = "auth_client_grants",
            joinColumns = @JoinColumn(
                    name = "client_id",              // coluna na tabela de grants
                    referencedColumnName = "client_id" // coluna na tabela auth_client_applications
            )
    )
    @Enumerated(EnumType.STRING)
    @Column(name = "grant_type", length = 32)
    private Set<GrantType> grantTypes;

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(
            name = "auth_client_redirect_uris",
            joinColumns = @JoinColumn(
                    name = "client_id",
                    referencedColumnName = "client_id"
            )
    )
    @Column(name = "redirect_uri", length = 512)
    private Set<String> redirectUris;

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(
            name = "auth_client_scopes",
            joinColumns = @JoinColumn(
                    name = "client_id",
                    referencedColumnName = "client_id"
            )
    )
    @Column(name = "scope", length = 64)
    private Set<String> scopes;

    @Column(name = "first_party", nullable = false)
    private boolean firstParty;

    @Column(name = "active", nullable = false)
    private boolean active;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

}
