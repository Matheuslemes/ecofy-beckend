package br.com.ecofy.auth.core.domain;

import br.com.ecofy.auth.core.domain.enums.ClientType;
import br.com.ecofy.auth.core.domain.enums.GrantType;

import java.time.Instant;
import java.util.*;

// client oauth2/oicd registrado no ms-auth
public class ClientApplication {

    private final String id; // internal id (UUID string)

    private final String clientId; // public client_id

    private String clientSecretHash;

    private final String name;

    private final ClientType clientType;

    private final Set<GrantType> grantTypes;

    private final Set<String> redirectUris;

    private final Set<String> scopes;

    private final boolean firstParty;

    private boolean active;

    private final Instant createdAt;

    private Instant updatedAt;

    private ClientApplication(String id,
                              String clientId,
                              String clientSecretHash,
                              String name,
                              ClientType clientType,
                              Set<GrantType> grantTypes,
                              Set<String> redirectUris,
                              Set<String> scopes,
                              boolean firstParty,
                              boolean active,
                              Instant createdAt,
                              Instant updatedAt) {

        this.id = Objects.requireNonNull(id);
        this.clientId = Objects.requireNonNull(clientId);
        this.clientSecretHash = clientSecretHash;
        this.name = Objects.requireNonNull(name);
        this.clientType = Objects.requireNonNull(clientType);
        this.grantTypes = grantTypes != null ? new HashSet<>(grantTypes) : new HashSet<>();
        this.redirectUris = redirectUris != null ? new HashSet<>(redirectUris) : new HashSet<>();
        this.scopes = scopes != null ? new HashSet<>(scopes) : new HashSet<>();
        this.firstParty = firstParty;
        this.active = active;
        this.createdAt = Objects.requireNonNull(createdAt);
        this.updatedAt = Objects.requireNonNull(updatedAt);
    }

    public static ClientApplication create(String name,
                                           ClientType clientType,
                                           Set<GrantType> grantTypes,
                                           Set<String> redirectUris,
                                           Set<String> scopes,
                                           boolean firstParty,
                                           String generatedClientId,
                                           String clientSecretHash) {

        Instant now = Instant.now();
        String internalId = UUID.randomUUID().toString();
        boolean active = true;

        return new ClientApplication(
                internalId,
                generatedClientId,
                clientSecretHash,
                name,
                clientType,
                grantTypes,
                redirectUris,
                scopes,
                firstParty,
                active,
                now,
                now
        );
    }

    public String id() {
        return id;
    }

    public String clientId() {
        return clientId;
    }

    public String clientSecretHash() {
        return clientSecretHash;
    }

    public String name() {
        return name;
    }

    public ClientType clientType() {
        return clientType;
    }

    public Set<GrantType> grantTypes() {
        return Collections.unmodifiableSet(grantTypes);
    }

    public Set<String> redirectUris() {
        return Collections.unmodifiableSet(redirectUris);
    }

    public Set<String> scopes() {
        return Collections.unmodifiableSet(scopes);
    }

    public boolean isFirstParty() {
        return firstParty;
    }

    public boolean isActive() {
        return active;
    }

    public Instant createdAt() {
        return createdAt;
    }

    public Instant updatedAt() {
        return updatedAt;
    }

    public boolean supportsGrant(GrantType grantType) {
        return grantTypes.contains(grantType);
    }

    public boolean supportsRedirectUri(String redirectUri) {
        return redirectUris.isEmpty() || redirectUris.contains(redirectUri);
    }

    public boolean supportsScope(String requestedScope) {
        return scopes.isEmpty() || scopes.contains(requestedScope);
    }

    public void rotateSecret(String newSecretHash) {
        this.clientSecretHash = Objects.requireNonNull(newSecretHash);
        touch();
    }

    public void deactivate() {
        this.active = false;
        touch();
    }

    private void touch() {
        this.updatedAt = Instant.now();
    }

}
