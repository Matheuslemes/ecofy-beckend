package br.com.ecofy.auth.core.domain;

import br.com.ecofy.auth.core.domain.enums.AuthUserStatus;
import br.com.ecofy.auth.core.domain.valueobject.AuthUserId;
import br.com.ecofy.auth.core.domain.valueobject.EmailAddress;
import br.com.ecofy.auth.core.domain.valueobject.PasswordHash;

import java.time.Instant;
import java.util.Collections;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

// raiz de agregado de usuario de autenticacao
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

    private AuthUser(AuthUserId id,
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

        this.id = Objects.requireNonNull(id);
        this.email = Objects.requireNonNull(email);
        this.passwordHash = Objects.requireNonNull(passwordHash);
        this.status = Objects.requireNonNull(status);
        this.emailVerified = emailVerified;
        this.firstName = firstName;
        this.lastName = lastName;
        this.locale = locale != null ? locale : "pt-BR";
        this.roles = roles != null ? new HashSet<>(roles) : new HashSet<>();
        this.directPermissions = directPermissions != null ? new HashSet<>(directPermissions) : new HashSet<>();
        this.createdAt = Objects.requireNonNull(createdAt);
        this.updatedAt = Objects.requireNonNull(updatedAt);
        this.lastLoginAt = lastLoginAt;
        this.failedLoginAttempts = failedLoginAttempts;
    }

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

    public Set<Role> roles() {
        return Collections.unmodifiableSet(roles);
    }

    public Set<Permission> directPermissions() {
        return Collections.unmodifiableSet(directPermissions);
    }

    // regras de negocio
    public String fullName() {
        return String.join(" ",
                Objects.toString(firstName, "").trim(),
                Objects.toString(lastName, "").trim()).trim();
    }

    public void confirmEmail() {
        if (status == AuthUserStatus.BLOCKED || status == AuthUserStatus.DELETED) {
            throw new  IllegalArgumentException("User not eligible to confirm email");
        }
        this.emailVerified = true;
        if (status == AuthUserStatus.PENDING_EMAIL_CONFIRMATION) {
            this.status = AuthUserStatus.ACTIVE;
        }
        touch();
    }

    private void touch() {
        this.updatedAt = Instant.now();
    }

    public void changePassword(PasswordHash newPasswordHash) {
        this.passwordHash = Objects.requireNonNull(newPasswordHash);
        this.failedLoginAttempts = 0;
        touch();
    }

    public void registerSuccessfulLogin() {
        this.failedLoginAttempts = 0;
        this.lastLoginAt = Instant.now();
        touch();
    }

    public void registerFailedLogin(int maxAttemptsBeforeLock) {
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
        this.roles.add(Objects.requireNonNull(role));
        touch();
    }

    public void addDirectPermission(Permission permission) {
        this.directPermissions.add(Objects.requireNonNull(permission));
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

}
