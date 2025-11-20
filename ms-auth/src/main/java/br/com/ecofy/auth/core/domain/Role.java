package br.com.ecofy.auth.core.domain;

import java.util.Collections;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

// papel de autorizacao, conjunto de Permissions
public final class Role {

    private final String name; // ROLE_ADMIN, ROLE_USER, etc

    private final String description;;

    private final Set<Permission> permissions;

    public Role(String name, String description, Set<Permission> permissions) {
        this.name = Objects.requireNonNull(name, "name must not be null");
        this.description = description;
        this.permissions = permissions != null ? new HashSet<>(permissions) : new HashSet<>();
    }

    public String name() {
        return name;
    }

    public String description() {
        return description;
    }

    public Set<Permission> permissions() {
        return Collections.unmodifiableSet(permissions);
    }

    public boolean hasPermission(String permissionName) {
        return permissions.stream()
                .anyMatch(p -> p.name().equals(permissionName));
    }

    public boolean implies(Permission permission) {
        return permissions.stream().anyMatch(p -> p.implies(permission));
    }

    @Override
    public String toString() {
        return name;
    }

    // equals/hashCode por name
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof Role role)) return false;
        return name.equals(role.name);
    }

    @Override
    public int hashCode() {
        return name.hashCode();
    }

}
