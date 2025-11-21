package br.com.ecofy.auth.core.domain;

import br.com.ecofy.auth.core.domain.enums.AuthUserStatus;
import br.com.ecofy.auth.core.domain.valueobject.AuthUserId;
import br.com.ecofy.auth.core.domain.valueobject.EmailAddress;
import br.com.ecofy.auth.core.domain.valueobject.PasswordHash;

import java.time.Instant;
import java.util.*;

// raix de agregado do usuario de autenticacao
public class AuthUser {

    private final AuthUserId id;

    private final EmailAddress email;

    private PasswordHash passwordHash;

    private AuthUserStatus status;

    private boolean emailVerified;

    private String firstName;

    private String lastName;

    private String locale;

    private final Set<Role> roles;

    private final Set<Permission> directPermissions;

    private final Instant createdAt;

    private Instant updatedAt;

    private Instant lastLoginAt;

    private int failedLoginAttempts;

    public AuthUser(AuthUserId id,
                    EmailAddress email,
                    PasswordHash passwordHash,
                    AuthUserStatus status,
                    boolean emailVerified,
                    String firstName,
                    String lastName,
                    String locale,
                    Set<Role> roles,
                    Set<Permission> directPermissions,
                    Instant createdAt,
                    Instant updatedAt,
                    Instant lastLoginAt,
                    int failedLoginAttempts) {

        this.id = Objects.requireNonNull(id, "id must not be null");
        this.email = Objects.requireNonNull(email, "email must not be null");
        this.passwordHash = Objects.requireNonNull(passwordHash, "passwordHash must not be null");
        this.status = Objects.requireNonNull(status, "status must not be null");
        this.emailVerified = emailVerified;
        this.firstName = firstName;
        this.lastName = lastName;
        this.locale = (locale != null && !locale.isBlank()) ? locale : "pt-BR";

        this.roles = roles != null ? new HashSet<>(roles) : new HashSet<>();
        this.directPermissions = directPermissions != null ? new HashSet<>(directPermissions) : new HashSet<>();

        this.createdAt = Objects.requireNonNull(createdAt, "createdAt must not be null");
        this.updatedAt = Objects.requireNonNull(updatedAt, "updatedAt must not be null");
        this.lastLoginAt = lastLoginAt;
        this.failedLoginAttempts = Math.max(failedLoginAttempts, 0);
    }

    // Factories
    public static AuthUser newPendingUser(EmailAddress email,
                                          PasswordHash passwordHash,
                                          String firstName,
                                          String lastName) {
        Instant now = Instant.now();
        return new AuthUser(
                AuthUserId.newId(),
                email,
                passwordHash,
                AuthUserStatus.PENDING_EMAIL_CONFIRMATION,
                false,
                firstName,
                lastName,
                "pt-BR",
                Set.of(),
                Set.of(),
                now,
                now,
                null,
                0
        );
    }

    // Getters (imutáveis / de leitura)
    public AuthUserId id() {
        return id;
    }

    public EmailAddress email() {
        return email;
    }

    public PasswordHash passwordHash() {
        return passwordHash;
    }

    public AuthUserStatus status() {
        return status;
    }

    public boolean isEmailVerified() {
        return emailVerified;
    }

    public String firstName() {
        return firstName;
    }

    public String lastName() {
        return lastName;
    }

    public String locale() {
        return locale;
    }

    public Instant createdAt() {
        return createdAt;
    }

    public Instant updatedAt() {
        return updatedAt;
    }

    public Instant lastLoginAt() {
        return lastLoginAt;
    }

    public int failedLoginAttempts() {
        return failedLoginAttempts;
    }

    public Set<Role> roles() {
        return Collections.unmodifiableSet(roles);
    }

    public Set<Permission> directPermissions() {
        return Collections.unmodifiableSet(directPermissions);
    }

    // Regras de negócio
    public String fullName() {
        String first = Objects.toString(firstName, "").trim();
        String last = Objects.toString(lastName, "").trim();
        return (first + " " + last).trim();
    }

    public void confirmEmail() {
        if (status == AuthUserStatus.BLOCKED || status == AuthUserStatus.DELETED) {
            throw new IllegalStateException("User is not eligible to confirm email");
        }
        this.emailVerified = true;
        if (status == AuthUserStatus.PENDING_EMAIL_CONFIRMATION) {
            this.status = AuthUserStatus.ACTIVE;
        }
        touch();
    }

    public void changePassword(PasswordHash newPasswordHash) {
        this.passwordHash = Objects.requireNonNull(newPasswordHash, "newPasswordHash must not be null");
        this.failedLoginAttempts = 0;
        touch();
    }

    public void registerSuccessfulLogin() {
        this.failedLoginAttempts = 0;
        this.lastLoginAt = Instant.now();
        touch();
    }

    public void registerFailedLogin(int maxAttemptsBeforeLock) {
        if (maxAttemptsBeforeLock <= 0) {
            throw new IllegalArgumentException("maxAttemptsBeforeLock must be greater than zero");
        }
        this.failedLoginAttempts++;
        if (failedLoginAttempts >= maxAttemptsBeforeLock) {
            this.status = AuthUserStatus.LOCKED;
        }
        touch();
    }

    public boolean hasPermission(String permissionName) {
        Permission required = new Permission(permissionName, null, "*");
        return roles.stream().anyMatch(r -> r.implies(required))
                || directPermissions.stream().anyMatch(p -> p.implies(required));
    }

    public void addRole(Role role) {
        this.roles.add(Objects.requireNonNull(role, "role must not be null"));
        touch();
    }

    public void addDirectPermission(Permission permission) {
        this.directPermissions.add(Objects.requireNonNull(permission, "permission must not be null"));
        touch();
    }

    public void block() {
        this.status = AuthUserStatus.BLOCKED;
        touch();
    }

    public void delete() {
        this.status = AuthUserStatus.DELETED;
        touch();
    }

    // Internals
    private void touch() {
        this.updatedAt = Instant.now();
    }

}
