package br.com.ecofy.auth.core.domain.events;

import br.com.ecofy.auth.core.domain.AuthUser;

import java.time.Instant;

public record UserRegisteredEvent(

        AuthUser user,
        Instant occurredAt

) {

    public UserRegisteredEvent(AuthUser user) {
        this(user, Instant.now());
    }

}
