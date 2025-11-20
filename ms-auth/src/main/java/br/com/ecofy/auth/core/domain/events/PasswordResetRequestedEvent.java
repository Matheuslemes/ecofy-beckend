package br.com.ecofy.auth.core.domain.events;

import br.com.ecofy.auth.core.domain.AuthUser;

import java.time.Instant;

public record PasswordResetRequestedEvent(

        AuthUser user,
        String resetToken,
        Instant occurredAt

) {

    public PasswordResetRequestedEvent(AuthUser user, String resetToken) {
        this(user, resetToken, Instant.now());
    }

}
