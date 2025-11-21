package br.com.ecofy.auth.core.domain;

import java.util.Locale;
import java.util.Objects;

/**
 * Permissão granular do sistema, por exemplo: "transactions:read".
 * Convenções:
 * - name: permissão completa, ex.: "transactions:read", "users:write"
 * - domain: agrupador lógico (ex.: "transactions", "users" ou "*")
 * - wildcards:
 *   - "*" implica qualquer permissão
 *   - "transactions:*" implica qualquer perm em "transactions:*"
 */
public final class Permission {

    private final String name;
    private final String description;
    private final String domain;

    public Permission(String name, String description, String domain) {
        this.name = normalizeName(name);
        this.description = description;
        this.domain = normalizeDomain(domain);
    }

    // Getters
    public String name() {
        return name;
    }

    public String description() {
        return description;
    }

    public String domain() {
        return domain;
    }

    // Regras de domínio

    /**
     * Verifica se esta permissão implica outra permissão.
     *
     * Regras:
     * - Se nomes forem iguais, implica.
     * - Se this.name == "*" -> implica qualquer permissão.
     * - Se this.name termina com ":*" -> implica qualquer permissão com mesmo prefixo.
     * - Domain, se não for "*", deve casar com o domain da outra permissão.
     */
    public boolean implies(Permission other) {
        Objects.requireNonNull(other, "other must not be null");

        // Global wildcard: "*" implica qualquer permissão
        if (isWildcard()) {
            return true;
        }

        // Se os domains forem específicos e diferentes, não implica
        if (!"*".equals(this.domain) &&
                !"*".equals(other.domain) &&
                !this.domain.equalsIgnoreCase(other.domain)) {
            return false;
        }

        // Mesmo nome => implica
        if (this.name.equals(other.name)) {
            return true;
        }

        // "transactions:*" implica "transactions:read", "transactions:write" etc.
        if (isDomainWildcardName()) {
            String prefix = this.name.substring(0, this.name.length() - 1); // remove o '*'
            return other.name.startsWith(prefix);
        }

        return false;
    }

    /**
     * Atalho para checar se esta permissão implica um nome de permissão bruto.
     */
    public boolean implies(String otherPermissionName) {
        return implies(new Permission(otherPermissionName, null, this.domain));
    }

    /**
     * Retorna true se a permissão é o wildcard global "*".
     */
    public boolean isWildcard() {
        return "*".equals(this.name);
    }

    /**
     * Retorna true se a permissão é do tipo "algo:*".
     */
    public boolean isDomainWildcardName() {
        return this.name.endsWith(":*") && this.name.length() > 2;
    }

    // Internals
    private String normalizeName(String rawName) {
        Objects.requireNonNull(rawName, "name must not be null");
        String trimmed = rawName.trim();
        if (trimmed.isEmpty()) {
            throw new IllegalArgumentException("name must not be blank");
        }
        // nome costuma ser case-sensitive, mas se quiser, normaliza aqui
        return trimmed;
    }

    private String normalizeDomain(String rawDomain) {
        if (rawDomain == null || rawDomain.isBlank()) {
            return "*";
        }
        return rawDomain.trim().toLowerCase(Locale.ROOT);
    }

    // equals / hashCode / toString

    // equals/hashCode por name (mantém comportamento atual)
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

    @Override
    public String toString() {
        return "Permission{" +
                "name='" + name + '\'' +
                ", domain='" + domain + '\'' +
                '}';
    }
}
