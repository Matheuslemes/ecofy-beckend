package br.com.ecofy.auth.core.domain;

import java.util.Objects;

// permissao granular do sistema, ex: transactions:read
public final class Permission {

    private final String name;

    private final String description;

    private final String domain;

    public Permission(String name, String description, String domain) {
        this.name = Objects.requireNonNull(name, "name must not be null");
        this.description = description;
        this.domain = domain != null ? domain : "*";
    }

    public String name() {
        return name;
    }

    public String description() {
        return description;
    }

    public String domain() {
        return domain;
    }

    // regras simples: "transactions:*" implica "transactions:read".
    public boolean implies(Permission other) {

        if (this.name.equals(other.name)) {
            return true;
        }

        if (this.name.endsWith(":*")) {
            String prefix = this.name.substring(0, this.name.length() - 1);
            return other.name.startsWith(prefix);
        }

        return false;

    }

    @Override
    public String toString() {
        return name;
    }

    // equals/hashCode por name
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof Permission that)) return false;
        return name.equals(that.name);
    }

    @Override
    public int hashCode() {
        return name.hashCode();
    }

}
