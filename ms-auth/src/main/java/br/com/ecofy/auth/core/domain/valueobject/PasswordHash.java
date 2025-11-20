package br.com.ecofy.auth.core.domain.valueobject;

import java.io.Serializable;
import java.util.Objects;

// encapsula o hash da senha para evitar uso acidental como string qualquer.
public final class PasswordHash implements Serializable {

    private final String value;

    public PasswordHash(String value) {
        this.value = Objects.requireNonNull(value, "password hash must not be null");
    }

    public String value() {
        return value;
    }

    @Override
    public String toString() {
        return "********";
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof PasswordHash that)) return false;
        return value.equals(that.value);
    }

    @Override
    public int hashCode() {
        return value.hashCode();
    }

}

