package br.com.ecofy.auth.core.application.service;

import br.com.ecofy.auth.core.domain.AuthUser;
import br.com.ecofy.auth.core.port.in.GetCurrentUserProfileUseCase;
import br.com.ecofy.auth.core.port.out.CurrentUserProviderPort;
import lombok.extern.slf4j.Slf4j;

import java.util.Objects;

/**
 * Serviço responsável por retornar o usuário autenticado atual.
 * Esta classe funciona como um "façade" de domínio para o adapter de segurança,
 * mantendo o domínio independente de Spring Security.
 */
@Slf4j
public class CurrentUserProfileService implements GetCurrentUserProfileUseCase {

    private final CurrentUserProviderPort currentUserProviderPort;

    public CurrentUserProfileService(CurrentUserProviderPort currentUserProviderPort) {
        this.currentUserProviderPort =
                Objects.requireNonNull(currentUserProviderPort, "currentUserProviderPort must not be null");
    }

    @Override
    public AuthUser getCurrentUser() {
        log.debug("[CurrentUserProfileService] - [getCurrentUser] -> Buscando usuário autenticado…");

        AuthUser user = currentUserProviderPort.getCurrentUserOrThrow();

        log.debug(
                "[CurrentUserProfileService] - [getCurrentUser] -> Usuário autenticado id={} email={} status={}",
                user.id().value(),
                user.email().value(),
                user.status()
        );

        return user;
    }
}
