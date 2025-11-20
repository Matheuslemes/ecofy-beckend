package br.com.ecofy.auth.core.domain.valueobject;

import java.io.Serializable;
import java.util.Objects;
import java.util.UUID;

// identidade de usuario no dominio
public final class AuthUserId implements Serializable {

    private final UUID value;

    public AuthUserId(UUID value) {
        this.value = Objects.requireNonNull(value, "value must not be null");
    }

    public static AuthUserId newId() {
        return new AuthUserId(UUID.randomUUID());
    }

    public UUID value() {
        return value;
    }

    @Override
    public String toString() {
        return value.toString();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof AuthUserId that)) return false;
        return Objects.equals(value, that.value);
    }

    @Override
    public int hashCode() {
        return Objects.hash(value);
    }

}
