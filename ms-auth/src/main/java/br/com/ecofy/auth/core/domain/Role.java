package br.com.ecofy.auth.core.domain;

import java.util.*;

/**
 * Papel de autorização do sistema, representando um conjunto de {@link Permission}.
 *
 * Convenção:
 * - name: geralmente no padrão "ROLE_ADMIN", "ROLE_USER", etc.
 */
public final class Role {

    private final String name; // ex.: ROLE_ADMIN, ROLE_USER
    private final String description;
    private final Set<Permission> permissions;

    public Role(String name, String description, Set<Permission> permissions) {
        this.name = normalizeName(name);
        this.description = description;
        this.permissions = permissions != null
                ? new HashSet<>(permissions)
                : new HashSet<>();
    }

    // Getters
    public String name() {
        return name;
    }

    public String description() {
        return description;
    }

    public Set<Permission> permissions() {
        return Collections.unmodifiableSet(permissions);
    }

    // Regras de domínio

    /**
     * Verifica se o role contém exatamente uma permissão com esse nome.
     * (sem considerar wildcards).
     */
    public boolean hasExactPermission(String permissionName) {
        Objects.requireNonNull(permissionName, "permissionName must not be null");
        return permissions.stream()
                .anyMatch(p -> p.name().equals(permissionName));
    }

    /**
     * Verifica se o role concede uma permissão que implique a permissão solicitada.
     * Usa a lógica de wildcard de {@link Permission#implies(Permission)}.
     */
    public boolean hasPermission(String permissionName) {
        Objects.requireNonNull(permissionName, "permissionName must not be null");
        Permission required = new Permission(permissionName, null, "*");
        return implies(required);
    }

    /**
     * Verifica se o role implica a permissão informada, considerando wildcards
     * como "transactions:*" ou "*" na permissão armazenada.
     */
    public boolean implies(Permission permission) {
        Objects.requireNonNull(permission, "permission must not be null");
        return permissions.stream().anyMatch(p -> p.implies(permission));
    }

    /**
     * Retorna um novo Role com a permissão adicionada.
     * Não modifica o atual (imutabilidade lógica da API).
     */
    public Role withPermission(Permission permission) {
        Objects.requireNonNull(permission, "permission must not be null");
        Set<Permission> newPerms = new HashSet<>(this.permissions);
        newPerms.add(permission);
        return new Role(this.name, this.description, newPerms);
    }

    /**
     * Retorna um novo Role sem a permissão informada.
     */
    public Role withoutPermission(Permission permission) {
        Objects.requireNonNull(permission, "permission must not be null");
        Set<Permission> newPerms = new HashSet<>(this.permissions);
        newPerms.remove(permission);
        return new Role(this.name, this.description, newPerms);
    }

    // Internals

    private String normalizeName(String rawName) {
        Objects.requireNonNull(rawName, "name must not be null");
        String trimmed = rawName.trim();
        if (trimmed.isEmpty()) {
            throw new IllegalArgumentException("name must not be blank");
        }

        // Se quiser forçar o prefixo ROLE_, descomenta:
        // if (!trimmed.startsWith("ROLE_")) {
        //     trimmed = "ROLE_" + trimmed;
        // }

        return trimmed;
    }

    // equals / hashCode / toString

    // equals/hashCode por name (mantém comportamento atual)
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

    @Override
    public String toString() {
        return "Role{" +
                "name='" + name + '\'' +
                ", permissionsCount=" + permissions.size() +
                '}';
    }
}
