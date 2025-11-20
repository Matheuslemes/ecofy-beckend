package br.com.ecofy.auth.core.domain.valueobject;

import java.io.Serializable;
import java.util.Objects;
import java.util.regex.Pattern;

// endereço de email com validacao basica
public final class EmailAddress implements Serializable {

    private static final Pattern SIMPLE_EMAIL_REGEX =
            Pattern.compile("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$");

    private final String value;

    public EmailAddress(String value) {
        Objects.requireNonNull(value, "email must not be null");
        String trimmed = value.trim().toLowerCase();
        if (!SIMPLE_EMAIL_REGEX.matcher(trimmed).matches()) {
            throw new IllegalArgumentException("Invalid email address: " + value);
        }
        this.value = trimmed;
    }

    public String value() {
        return value;
    }

    @Override
    public String toString() {
        return value;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof EmailAddress that)) return false;
        return value.equals(that.value);
    }

    @Override
    public int hashCode() {
        return value.hashCode();
    }

}
