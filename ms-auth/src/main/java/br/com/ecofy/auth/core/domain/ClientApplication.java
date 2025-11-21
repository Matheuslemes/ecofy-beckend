package br.com.ecofy.auth.core.domain;

import br.com.ecofy.auth.core.domain.enums.ClientType;
import br.com.ecofy.auth.core.domain.enums.GrantType;

import java.time.Instant;
import java.util.*;

/**
 * Agregado que representa um client OAuth2/OIDC registrado no ms-auth.
 * Responsável por encapsular:
 *  - tipo do client (confidential/public)
 *  - grants suportados
 *  - redirect URIs válidas
 *  - scopes permitidos
 *  - informações de auditoria (createdAt/updatedAt)
 */
public class ClientApplication {

    /** Identificador interno (UUID string). Nunca exposto a clientes. */
    private final String id;

    /** Identificador público usado como client_id no protocolo OAuth2/OIDC. */
    private final String clientId;

    /** Hash do client_secret (nunca armazenar o segredo em texto puro). */
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

    public ClientApplication(String id,
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

        this.id = Objects.requireNonNull(id, "id must not be null");
        this.clientId = Objects.requireNonNull(clientId, "clientId must not be null");
        this.name = Objects.requireNonNull(name, "name must not be null");
        this.clientType = Objects.requireNonNull(clientType, "clientType must not be null");
        this.createdAt = Objects.requireNonNull(createdAt, "createdAt must not be null");
        this.updatedAt = Objects.requireNonNull(updatedAt, "updatedAt must not be null");

        // client_secret pode ser opcional para PUBLIC, obrigatório para CONFIDENTIAL
        if (clientType == ClientType.CONFIDENTIAL &&
                (clientSecretHash == null || clientSecretHash.isBlank())) {
            throw new IllegalArgumentException("clientSecretHash must be provided for CONFIDENTIAL clients");
        }
        this.clientSecretHash = clientSecretHash;

        this.grantTypes = grantTypes != null
                ? new HashSet<>(grantTypes)
                : new HashSet<>();

        this.redirectUris = normalizeUriSet(redirectUris);
        this.scopes = normalizeScopeSet(scopes);

        this.firstParty = firstParty;
        this.active = active;
    }

    /**
     * Fábrica padrão para registrar um novo client.
     */
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
                Objects.requireNonNull(generatedClientId, "generatedClientId must not be null"),
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

    // Getters (somente leitura / imutáveis externamente)
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

    // Regras de negócio
    public boolean supportsGrant(GrantType grantType) {
        return grantTypes.contains(Objects.requireNonNull(grantType, "grantType must not be null"));
    }

    /**
     * Se não houver redirect URIs configuradas, consideramos que qualquer redirect_uri é inválida.
     * (comportamento mais seguro; se quiser manter "liberado" basta voltar ao comportamento anterior)
     */
    public boolean supportsRedirectUri(String redirectUri) {
        Objects.requireNonNull(redirectUri, "redirectUri must not be null");
        if (redirectUris.isEmpty()) {
            return false;
        }
        return redirectUris.contains(redirectUri.trim());
    }

    /**
     * Se nenhuma scope for configurada, assume-se que nenhuma scope é permitida.
     * (mais seguro que "tudo liberado")
     */
    public boolean supportsScope(String requestedScope) {
        Objects.requireNonNull(requestedScope, "requestedScope must not be null");
        if (scopes.isEmpty()) {
            return false;
        }
        return scopes.contains(requestedScope.trim());
    }

    /**
     * Verifica se o client suporta todas as scopes solicitadas.
     */
    public boolean supportsAllScopes(Set<String> requestedScopes) {
        if (requestedScopes == null || requestedScopes.isEmpty()) {
            return true; // nada solicitado, sempre ok
        }
        if (scopes.isEmpty()) {
            return false;
        }
        return requestedScopes.stream()
                .filter(Objects::nonNull)
                .map(String::trim)
                .allMatch(scopes::contains);
    }

    /**
     * Rotaciona o segredo do client. Só é permitido para clients CONFIDENTIAL.
     */
    public void rotateSecret(String newSecretHash) {
        if (clientType != ClientType.CONFIDENTIAL) {
            throw new IllegalStateException("Only CONFIDENTIAL clients can have a secret");
        }
        this.clientSecretHash = Objects.requireNonNull(newSecretHash, "newSecretHash must not be null");
        touch();
    }

    /**
     * Desativa o client (não deve mais ser usado em novos fluxos OAuth2/OIDC).
     */
    public void deactivate() {
        if (!this.active) {
            return;
        }
        this.active = false;
        touch();
    }

    /**
     * Reativa o client (caso tenha sido desativado).
     */
    public void activate() {
        if (this.active) {
            return;
        }
        this.active = true;
        touch();
    }

    // Internals
    private void touch() {
        this.updatedAt = Instant.now();
    }

    private static Set<String> normalizeScopeSet(Set<String> scopes) {
        if (scopes == null || scopes.isEmpty()) {
            return new HashSet<>();
        }
        Set<String> normalized = new HashSet<>();
        for (String scope : scopes) {
            if (scope != null) {
                String trimmed = scope.trim();
                if (!trimmed.isEmpty()) {
                    normalized.add(trimmed);
                }
            }
        }
        return normalized;
    }

    private static Set<String> normalizeUriSet(Set<String> uris) {
        if (uris == null || uris.isEmpty()) {
            return new HashSet<>();
        }
        Set<String> normalized = new HashSet<>();
        for (String uri : uris) {
            if (uri != null) {
                String trimmed = uri.trim();
                if (!trimmed.isEmpty()) {
                    normalized.add(trimmed);
                }
            }
        }
        return normalized;
    }
}
