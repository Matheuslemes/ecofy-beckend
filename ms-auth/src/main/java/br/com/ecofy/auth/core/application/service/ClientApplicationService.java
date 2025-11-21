package br.com.ecofy.auth.core.application.service;

import br.com.ecofy.auth.core.domain.ClientApplication;
import br.com.ecofy.auth.core.domain.enums.ClientType;
import br.com.ecofy.auth.core.domain.enums.GrantType;
import br.com.ecofy.auth.core.port.in.RegisterClientApplicationUseCase;
import br.com.ecofy.auth.core.port.out.PasswordHashingPort;
import br.com.ecofy.auth.core.port.out.SaveClientApplicationPort;
import lombok.extern.slf4j.Slf4j;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.Objects;
import java.util.Set;

@Slf4j
public class ClientApplicationService implements RegisterClientApplicationUseCase {

    private final SaveClientApplicationPort saveClientApplicationPort;
    private final PasswordHashingPort passwordHashingPort;
    private final SecureRandom secureRandom = new SecureRandom();

    public ClientApplicationService(SaveClientApplicationPort saveClientApplicationPort,
                                    PasswordHashingPort passwordHashingPort) {
        this.saveClientApplicationPort = Objects.requireNonNull(saveClientApplicationPort, "saveClientApplicationPort must not be null");
        this.passwordHashingPort = Objects.requireNonNull(passwordHashingPort, "passwordHashingPort must not be null");
    }

    @Override
    public ClientApplication register(RegisterClientCommand command) {
        Objects.requireNonNull(command, "command must not be null");

        log.debug(
                "[ClientApplicationService] - [register] -> Registrando novo client name={} type={} firstParty={}",
                command.name(), command.clientType(), command.firstParty()
        );

        // 1) Resolve clientId + secret bruto (apenas para clients que exigem segredo)
        String clientId = generateClientId(command.name());
        String rawSecret = requiresSecret(command.clientType())
                ? generateSecret()
                : null;

        if (rawSecret != null) {
            log.debug(
                    "[ClientApplicationService] - [register] -> Client requer segredo gerado clientId={} type={}",
                    clientId, command.clientType()
            );
        } else {
            log.debug(
                    "[ClientApplicationService] - [register] -> Client não requer segredo clientId={} type={}",
                    clientId, command.clientType()
            );
        }

        String secretHash = rawSecret != null
                ? passwordHashingPort.hash(rawSecret).value()
                : null;

        // 2) Resolve grants efetivos (pedido do command ou defaults por tipo)
        Set<GrantType> effectiveGrants = resolveEffectiveGrants(
                command.clientType(),
                command.grantTypes()
        );

        log.debug(
                "[ClientApplicationService] - [register] -> Grants resolvidos para clientId={} grants={}",
                clientId, effectiveGrants
        );

        // 3) Valida combinação ClientType × GrantType e redirects
        validateGrants(command.clientType(), effectiveGrants);
        validateRedirectUrisIfNeeded(effectiveGrants, command.redirectUris());

        // 4) Cria o agregado de domínio
        ClientApplication client = ClientApplication.create(
                command.name(),
                command.clientType(),
                effectiveGrants,
                command.redirectUris(),
                command.scopes(),
                command.firstParty(),
                clientId,
                secretHash
        );

        ClientApplication saved = saveClientApplicationPort.save(client);

        log.debug(
                "[ClientApplicationService] - [register] -> Client registrado com sucesso clientId={} type={} active={}",
                saved.clientId(), saved.clientType(), saved.isActive()
        );

        // IMPORTANTE: o rawSecret precisa ser retornado por fora (DTO/handler);
        // o agregado guarda apenas o hash.
        return saved;
    }

    // Regras de secret
    private boolean requiresSecret(ClientType clientType) {
        return clientType == ClientType.CONFIDENTIAL
                || clientType == ClientType.MACHINE_TO_MACHINE;
    }

    // ========================================================================
    // Grants / validações
    // ========================================================================

    /**
     * Se o comando não mandar grants, escolhemos defaults por tipo de client.
     */
    private Set<GrantType> resolveEffectiveGrants(ClientType clientType,
                                                  Set<GrantType> requested) {

        if (requested != null && !requested.isEmpty()) {
            return requested;
        }

        // Defaults por tipo
        return switch (clientType) {
            case CONFIDENTIAL -> Set.of(
                    GrantType.AUTHORIZATION_CODE,
                    GrantType.REFRESH_TOKEN,
                    GrantType.CLIENT_CREDENTIALS
            );
            case PUBLIC, SPA -> Set.of(
                    GrantType.AUTHORIZATION_CODE,
                    GrantType.REFRESH_TOKEN
            );
            case MACHINE_TO_MACHINE -> Set.of(
                    GrantType.CLIENT_CREDENTIALS
            );
        };
    }

    private void validateGrants(ClientType clientType, Set<GrantType> grants) {
        switch (clientType) {
            case MACHINE_TO_MACHINE -> {
                if (!grants.contains(GrantType.CLIENT_CREDENTIALS)) {
                    log.warn(
                            "[ClientApplicationService] - [validateGrants] -> M2M sem CLIENT_CREDENTIALS grants={}",
                            grants
                    );
                    throw new IllegalArgumentException("M2M client must support CLIENT_CREDENTIALS grant");
                }
                for (GrantType g : grants) {
                    if (g == GrantType.AUTHORIZATION_CODE || g == GrantType.PASSWORD) {
                        log.warn(
                                "[ClientApplicationService] - [validateGrants] -> Grant inválido para M2M grant={} grants={}",
                                g, grants
                        );
                        throw new IllegalArgumentException("M2M client cannot use " + g + " grant");
                    }
                }
            }
            case PUBLIC, SPA -> {
                if (grants.contains(GrantType.CLIENT_CREDENTIALS)) {
                    log.warn(
                            "[ClientApplicationService] - [validateGrants] -> PUBLIC/SPA com CLIENT_CREDENTIALS grants={}",
                            grants
                    );
                    throw new IllegalArgumentException("PUBLIC/SPA clients cannot use CLIENT_CREDENTIALS grant");
                }
            }
            case CONFIDENTIAL -> {
                // em confidential é mais flexível, por enquanto sem regras extras
            }
        }
    }

    private void validateRedirectUrisIfNeeded(Set<GrantType> grants, Set<String> redirectUris) {
        if (grants.contains(GrantType.AUTHORIZATION_CODE)) {
            if (redirectUris == null || redirectUris.isEmpty()) {
                log.warn(
                        "[ClientApplicationService] - [validateRedirectUrisIfNeeded] -> AUTHORIZATION_CODE sem redirectUris"
                );
                throw new IllegalArgumentException(
                        "AUTHORIZATION_CODE grant requires at least one redirectUri configured"
                );
            }
        }
    }

    // ========================================================================
    // Geração de credenciais
    // ========================================================================

    private String generateClientId(String name) {
        byte[] bytes = new byte[12];
        secureRandom.nextBytes(bytes);
        String clientId = "eco_" + Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(bytes);

        log.debug(
                "[ClientApplicationService] - [generateClientId] -> clientId gerado name={} clientId={}",
                name, clientId
        );

        return clientId;
    }

    private String generateSecret() {
        byte[] bytes = new byte[32];
        secureRandom.nextBytes(bytes);
        String secret = Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(bytes);

        // NUNCA logar o secret, apenas o fato de que foi gerado
        log.debug(
                "[ClientApplicationService] - [generateSecret] -> clientSecret gerado (valor não será logado)"
        );

        return secret;
    }
}
