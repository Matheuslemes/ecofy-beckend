package br.com.ecofy.auth.adapters.out.persistence;

import br.com.ecofy.auth.adapters.out.persistence.entity.*;
import br.com.ecofy.auth.core.domain.*;
import br.com.ecofy.auth.core.domain.enums.GrantType;
import br.com.ecofy.auth.core.domain.valueobject.AuthUserId;
import br.com.ecofy.auth.core.domain.valueobject.EmailAddress;
import br.com.ecofy.auth.core.domain.valueobject.PasswordHash;

import java.util.Collections;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

final class PersistenceMapper {

    private PersistenceMapper() {
        throw new AssertionError("PersistenceMapper is a utility class and should not be instantiated");
    }

    // ================== AuthUser ==================
    static AuthUserEntity toEntity(AuthUser user) {
        Objects.requireNonNull(user, "user must not be null");

        AuthUserEntity entity = new AuthUserEntity();
        entity.setId(user.id().value());          // UUID
        entity.setEmail(user.email().value());
        entity.setPasswordHash(user.passwordHash().value());
        entity.setStatus(user.status());
        entity.setEmailVerified(user.isEmailVerified());
        entity.setFirstName(user.firstName());
        entity.setLastName(user.lastName());
        entity.setLocale(user.locale());
        entity.setCreatedAt(user.createdAt());
        entity.setUpdatedAt(user.updatedAt());
        entity.setLastLoginAt(user.lastLoginAt());
        entity.setFailedLoginAttempts(user.failedLoginAttempts());

        // Roles/permissions via relacionamentos JPA (evita duplicidade de fonte de verdade)

        return entity;
    }

    static AuthUser toDomain(
            AuthUserEntity e,
            Set<RoleEntity> roleEntities,
            Set<PermissionEntity> permEntities
    ) {
        Objects.requireNonNull(e, "AuthUserEntity must not be null");

        Set<RoleEntity> safeRoleEntities =
                roleEntities == null ? Collections.emptySet() : roleEntities;

        Set<PermissionEntity> safePermEntities =
                permEntities == null ? Collections.emptySet() : permEntities;

        Set<Role> roles = safeRoleEntities.stream()
                .filter(Objects::nonNull)
                .map(PersistenceMapper::toDomain)
                .collect(Collectors.toUnmodifiableSet());

        Set<Permission> perms = safePermEntities.stream()
                .filter(Objects::nonNull)
                .map(PersistenceMapper::toDomain)
                .collect(Collectors.toUnmodifiableSet());

        return new AuthUser(
                new AuthUserId(e.getId()),              // UUID -> AuthUserId
                new EmailAddress(e.getEmail()),
                new PasswordHash(e.getPasswordHash()),
                e.getStatus(),
                e.isEmailVerified(),
                e.getFirstName(),
                e.getLastName(),
                e.getLocale(),
                roles,
                perms,
                e.getCreatedAt(),
                e.getUpdatedAt(),
                e.getLastLoginAt(),
                e.getFailedLoginAttempts()
        );
    }

    static Role toDomain(RoleEntity e) {
        Objects.requireNonNull(e, "RoleEntity must not be null");

        Set<Permission> perms =
                (e.getPermissions() == null ? Collections.<PermissionEntity>emptySet() : e.getPermissions())
                        .stream()
                        .filter(Objects::nonNull)
                        .map(PersistenceMapper::toDomain)
                        .collect(Collectors.toUnmodifiableSet());

        return new Role(e.getName(), e.getDescription(), perms);
    }

    static Permission toDomain(PermissionEntity e) {
        Objects.requireNonNull(e, "PermissionEntity must not be null");
        return new Permission(e.getName(), e.getDescription(), e.getDomain());
    }

    // ================== ClientApplication ==================
    static ClientApplication toDomain(ClientApplicationEntity e) {
        Objects.requireNonNull(e, "ClientApplicationEntity must not be null");

        Set<GrantType> grantTypes = e.getGrantTypes() == null
                ? Collections.emptySet()
                : e.getGrantTypes().stream()
                .filter(Objects::nonNull)
                .collect(Collectors.toUnmodifiableSet());

        Set<String> redirectUris = e.getRedirectUris() == null
                ? Collections.emptySet()
                : e.getRedirectUris().stream()
                .filter(Objects::nonNull)
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .collect(Collectors.toUnmodifiableSet());

        Set<String> scopes = e.getScopes() == null
                ? Collections.emptySet()
                : e.getScopes().stream()
                .filter(Objects::nonNull)
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .collect(Collectors.toUnmodifiableSet());

        return new ClientApplication(
                e.getId(),
                e.getClientId(),
                e.getClientSecretHash(),
                e.getName(),
                e.getClientType(),
                grantTypes,
                redirectUris,
                scopes,
                e.isFirstParty(),
                e.isActive(),
                e.getCreatedAt(),
                e.getUpdatedAt()
        );
    }

    static ClientApplicationEntity toEntity(ClientApplication c) {
        Objects.requireNonNull(c, "clientApplication must not be null");

        return ClientApplicationEntity.builder()
                .id(c.id())
                .clientId(c.clientId())
                .clientSecretHash(c.clientSecretHash())
                .name(c.name())
                .clientType(c.clientType())
                .grantTypes(c.grantTypes())
                .redirectUris(c.redirectUris())
                .scopes(c.scopes())
                .firstParty(c.isFirstParty())
                .active(c.isActive())
                .createdAt(c.createdAt())
                .updatedAt(c.updatedAt())
                .build();
    }

    // ================== RefreshToken ==================
    static RefreshToken toDomain(RefreshTokenEntity e) {
        Objects.requireNonNull(e, "RefreshTokenEntity must not be null");

        return new RefreshToken(
                e.getId(),                              // UUID
                e.getTokenValue(),
                new AuthUserId(e.getUserId()),          // UUID -> AuthUserId
                e.getClientId(),
                e.getIssuedAt(),
                e.getExpiresAt(),
                e.isRevoked(),
                e.getType()                             // TokenType (enum)
        );
    }

    static RefreshTokenEntity toEntity(RefreshToken t) {
        Objects.requireNonNull(t, "refreshToken must not be null");

        return RefreshTokenEntity.builder()
                .id(t.id())                             // UUID
                .tokenValue(t.tokenValue())
                .userId(t.userId().value())             // AuthUserId -> UUID
                .clientId(t.clientId())
                .issuedAt(t.issuedAt())
                .expiresAt(t.expiresAt())
                .revoked(t.isRevoked())
                .type(t.type())                         // usa o enum vindo do domínio
                .build();
    }

    // ================== JWK ==================
    static JwkKey toDomain(JwkKeyEntity e) {
        Objects.requireNonNull(e, "JwkKeyEntity must not be null");

        return new JwkKey(
                e.getKeyId(),
                e.getPublicKeyPem(),
                e.getAlgorithm(),
                e.getUse(),
                e.getCreatedAt(),
                e.isActive()
        );
    }
}
