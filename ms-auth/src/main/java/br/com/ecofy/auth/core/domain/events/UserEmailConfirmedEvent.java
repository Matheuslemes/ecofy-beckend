package br.com.ecofy.auth.core.domain.events;

import br.com.ecofy.auth.core.domain.AuthUser;

import java.time.Instant;

public record UserEmailConfirmedEvent(

        AuthUser user,
        Instant occurredAt

) {

    public UserEmailConfirmedEvent(AuthUser user) {
        this(user, Instant.now());
    }

}
