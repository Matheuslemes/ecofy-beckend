package br.com.ecofy.auth.adapters.out.persistence;

import br.com.ecofy.auth.adapters.out.persistence.entity.RefreshTokenEntity;
import br.com.ecofy.auth.adapters.out.persistence.repository.RefreshTokenRepository;
import br.com.ecofy.auth.core.domain.RefreshToken;
import br.com.ecofy.auth.core.port.out.RefreshTokenStorePort;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.Objects;
import java.util.Optional;

@Component
@Slf4j
public class RefreshTokenJpaAdapter implements RefreshTokenStorePort {

    private final RefreshTokenRepository repository;

    public RefreshTokenJpaAdapter(RefreshTokenRepository repository) {
        this.repository = Objects.requireNonNull(repository, "repository must not be null");
    }

    // SAVE
    @Override
    @Transactional
    public RefreshToken save(RefreshToken token) {
        Objects.requireNonNull(token, "token must not be null");

        log.debug(
                "[RefreshTokenJpaAdapter] - [save] -> Salvando refreshToken id={} userId={} clientId={}",
                token.id(), token.userId().value(), token.clientId()
        );

        RefreshTokenEntity entity = PersistenceMapper.toEntity(token);
        RefreshTokenEntity saved = repository.save(entity);

        log.debug(
                "[RefreshTokenJpaAdapter] - [save] -> RefreshToken persistido id={} revoked={}",
                saved.getId(), saved.isRevoked()
        );

        return PersistenceMapper.toDomain(saved);
    }

    // FIND BY TOKEN VALUE
    @Override
    @Transactional(readOnly = true)
    public Optional<RefreshToken> findByTokenValue(String tokenValue) {
        Objects.requireNonNull(tokenValue, "tokenValue must not be null");

        log.debug(
                "[RefreshTokenJpaAdapter] - [findByTokenValue] -> Buscando refreshToken tokenValue={}",
                tokenValue
        );

        return repository.findByTokenValue(tokenValue)
                .map(entity -> {
                    log.debug(
                            "[RefreshTokenJpaAdapter] - [findByTokenValue] -> RefreshToken encontrado id={} revoked={}",
                            entity.getId(), entity.isRevoked()
                    );
                    return PersistenceMapper.toDomain(entity);
                });
    }

    // REVOKE
    @Override
    @Transactional
    public void revoke(String tokenValue) {
        Objects.requireNonNull(tokenValue, "tokenValue must not be null");

        log.debug(
                "[RefreshTokenJpaAdapter] - [revoke] -> Revogando refreshToken tokenValue={}",
                tokenValue
        );

        repository.findByTokenValue(tokenValue).ifPresentOrElse(entity -> {
            if (!entity.isRevoked()) {
                entity.setRevoked(true);
                repository.save(entity);

                log.debug(
                        "[RefreshTokenJpaAdapter] - [revoke] -> RefreshToken revogado id={} tokenValue={}",
                        entity.getId(), tokenValue
                );
            } else {
                log.debug(
                        "[RefreshTokenJpaAdapter] - [revoke] -> RefreshToken já estava revogado id={} tokenValue={}",
                        entity.getId(), tokenValue
                );
            }
        }, () -> log.debug(
                "[RefreshTokenJpaAdapter] - [revoke] -> Nenhum refreshToken encontrado para tokenValue={}",
                tokenValue
        ));
    }
}
