package br.com.ecofy.auth.adapters.out.persistence;

import br.com.ecofy.auth.adapters.out.persistence.entity.AuthUserEntity;
import br.com.ecofy.auth.adapters.out.persistence.repository.AuthUserRepository;
import br.com.ecofy.auth.core.domain.AuthUser;
import br.com.ecofy.auth.core.domain.valueobject.AuthUserId;
import br.com.ecofy.auth.core.domain.valueobject.EmailAddress;
import br.com.ecofy.auth.core.port.out.LoadAuthUserByEmailPort;
import br.com.ecofy.auth.core.port.out.LoadAuthUserByIdPort;
import br.com.ecofy.auth.core.port.out.SaveAuthUserPort;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Objects;
import java.util.Optional;

@Component
@Slf4j
public class AuthUserJpaAdapter implements SaveAuthUserPort, LoadAuthUserByEmailPort, LoadAuthUserByIdPort {

    private final AuthUserRepository authUserRepository;

    public AuthUserJpaAdapter(AuthUserRepository authUserRepository) {
        this.authUserRepository = Objects.requireNonNull(authUserRepository, "authUserRepository must not be null");
    }

    @Override
    @Transactional
    public AuthUser save(AuthUser user) {
        Objects.requireNonNull(user, "user must not be null");

        Instant now = Instant.now();
        String userId = user.id().value().toString();

        log.debug("[AuthUserJpaAdapter] - [save] -> Persistindo usuário id={} email={}",
                userId, user.email().value());

        AuthUserEntity entity = authUserRepository.findById(user.id().value())
                .map(existing -> {
                    log.debug("[AuthUserJpaAdapter] - [save] -> Atualizando usuário existente id={}", userId);
                    return existing;
                })
                .orElseGet(() -> {
                    log.debug("[AuthUserJpaAdapter] - [save] -> Criando novo usuário id={}", userId);
                    AuthUserEntity e = new AuthUserEntity();
                    e.setId(user.id().value());
                    e.setCreatedAt(now);
                    return e;
                });

        mapDomainToEntity(user, entity, now);

        AuthUserEntity saved = authUserRepository.save(entity);

        log.debug("[AuthUserJpaAdapter] - [save] -> Usuário persistido com sucesso id={} email={}",
                saved.getId(), saved.getEmail());

        // Se no futuro tiver coleções de roles/perms mapeadas com @ManyToMany/@OneToMany,
        // o PersistenceMapper centraliza esse carregamento.
        return PersistenceMapper.toDomain(saved, saved.getRoles(), saved.getPermissions());
    }

    @Override
    @Transactional(readOnly = true)
    public Optional<AuthUser> loadByEmail(EmailAddress email) {
        Objects.requireNonNull(email, "email must not be null");

        log.debug("[AuthUserJpaAdapter] - [loadByEmail] -> Buscando usuário por email={}", email.value());

        return authUserRepository.findByEmailIgnoreCase(email.value())
                .map(entity -> {
                    log.debug("[AuthUserJpaAdapter] - [loadByEmail] -> Usuário encontrado id={} email={}",
                            entity.getId(), entity.getEmail());
                    return PersistenceMapper.toDomain(entity, entity.getRoles(), entity.getPermissions());
                });
    }

    @Override
    @Transactional(readOnly = true)
    public Optional<AuthUser> loadById(AuthUserId id) {
        Objects.requireNonNull(id, "id must not be null");

        log.debug("[AuthUserJpaAdapter] - [loadById] -> Buscando usuário por id={}", id.value());

        return authUserRepository.findById(id.value())
                .map(entity -> {
                    log.debug("[AuthUserJpaAdapter] - [loadById] -> Usuário encontrado id={} email={}",
                            entity.getId(), entity.getEmail());
                    return PersistenceMapper.toDomain(entity, entity.getRoles(), entity.getPermissions());
                });
    }

    // =========================================================
    // Mapeamento domínio -> entidade
    // =========================================================

    private void mapDomainToEntity(AuthUser user, AuthUserEntity entity, Instant now) {
        entity.setEmail(user.email().value());
        entity.setPasswordHash(user.passwordHash().value());
        entity.setStatus(user.status());
        entity.setEmailVerified(user.isEmailVerified());
        entity.setFirstName(user.firstName());
        entity.setLastName(user.lastName());
        entity.setLocale(user.locale());
        entity.setLastLoginAt(user.lastLoginAt());

        // garante createdAt preenchido mesmo se alguém criar entidade "na mão"
        if (entity.getCreatedAt() == null) {
            entity.setCreatedAt(now);
        }
        entity.setUpdatedAt(now);

        // TODO: mapear roles/perms quando a modelagem de relacionamento estiver fechada
        // ex: entity.setRoles(roleMapper.toEntities(user.roles()));
        //      entity.setPermissions(permissionMapper.toEntities(user.directPermissions()));
    }
}
