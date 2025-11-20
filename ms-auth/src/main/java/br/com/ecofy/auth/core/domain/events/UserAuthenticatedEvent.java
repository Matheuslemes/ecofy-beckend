package br.com.ecofy.auth.core.domain.events;

import br.com.ecofy.auth.core.domain.AuthUser;
import br.com.ecofy.auth.core.domain.ClientApplication;

import java.time.Instant;

public record UserAuthenticatedEvent(

        AuthUser user,
        ClientApplication client,
        String ipAddress,
        Instant occurredAt

) {

    public UserAuthenticatedEvent(AuthUser user, ClientApplication client, String ipAddress) {
        this(user, client, ipAddress, Instant.now());
    }

}
