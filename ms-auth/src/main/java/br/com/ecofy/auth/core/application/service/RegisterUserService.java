package br.com.ecofy.auth.core.application.service;

import br.com.ecofy.auth.core.domain.AuthUser;
import br.com.ecofy.auth.core.domain.event.UserRegisteredEvent;
import br.com.ecofy.auth.core.domain.valueobject.EmailAddress;
import br.com.ecofy.auth.core.domain.valueobject.PasswordHash;
import br.com.ecofy.auth.core.port.in.RegisterUserUseCase;
import br.com.ecofy.auth.core.port.out.*;
import lombok.extern.slf4j.Slf4j;

import java.util.Objects;
import java.util.UUID;

/**
 * Serviço responsável pelo fluxo completo de registro de um usuário:
 *  - validações de email
 *  - criação do usuário
 *  - hashing seguro da senha
 *  - envio do e-mail de verificação (opcional)
 *  - publicação de evento de domínio
 */
@Slf4j
public class RegisterUserService implements RegisterUserUseCase {

    private final SaveAuthUserPort saveAuthUserPort;
    private final LoadAuthUserByEmailPort loadAuthUserByEmailPort;
    private final PasswordHashingPort passwordHashingPort;
    private final SendVerificationEmailPort sendVerificationEmailPort;
    private final VerificationTokenStorePort verificationTokenStorePort;
    private final PublishAuthEventPort publishAuthEventPort;

    public RegisterUserService(SaveAuthUserPort saveAuthUserPort,
                               LoadAuthUserByEmailPort loadAuthUserByEmailPort,
                               PasswordHashingPort passwordHashingPort,
                               SendVerificationEmailPort sendVerificationEmailPort,
                               VerificationTokenStorePort verificationTokenStorePort,
                               PublishAuthEventPort publishAuthEventPort) {

        this.saveAuthUserPort = Objects.requireNonNull(saveAuthUserPort, "saveAuthUserPort must not be null");
        this.loadAuthUserByEmailPort = Objects.requireNonNull(loadAuthUserByEmailPort, "loadAuthUserByEmailPort must not be null");
        this.passwordHashingPort = Objects.requireNonNull(passwordHashingPort, "passwordHashingPort must not be null");
        this.sendVerificationEmailPort = Objects.requireNonNull(sendVerificationEmailPort, "sendVerificationEmailPort must not be null");
        this.verificationTokenStorePort = Objects.requireNonNull(verificationTokenStorePort, "verificationTokenStorePort must not be null");
        this.publishAuthEventPort = Objects.requireNonNull(publishAuthEventPort, "publishAuthEventPort must not be null");
    }

    @Override
    public AuthUser register(RegisterUserCommand command) {
        Objects.requireNonNull(command, "command must not be null");

        EmailAddress email = new EmailAddress(command.email());

        log.debug(
                "[RegisterUserService] - [register] -> Iniciando registro de usuário email={} firstName={} lastName={}",
                email.value(), command.firstName(), command.lastName()
        );

        // 1 — Verifica se já existe usuário com o email informado
        loadAuthUserByEmailPort.loadByEmail(email).ifPresent(existing -> {
            log.warn(
                    "[RegisterUserService] - [register] -> Email já registrado email={} userId={}",
                    email.value(), existing.id().value()
            );
            throw new IllegalArgumentException("Email already registered");
        });

        // 2 — Hash seguro da senha
        PasswordHash passwordHash = passwordHashingPort.hash(command.rawPassword());

        // 3 — Criação do agregado AuthUser (pending ou confirmado)
        AuthUser newUser = AuthUser.newPendingUser(
                email,
                passwordHash,
                command.firstName(),
                command.lastName()
        );

        if (command.autoConfirmEmail()) {
            log.debug(
                    "[RegisterUserService] - [register] -> Auto-confirmando email={} userStatusBefore={}",
                    email.value(),
                    newUser.status()
            );
            newUser.confirmEmail();
        }

        // 4 — Persistência
        AuthUser persisted = saveAuthUserPort.save(newUser);

        log.debug(
                "[RegisterUserService] - [register] -> Usuário persistido userId={} emailVerified={}",
                persisted.id().value(),
                persisted.isEmailVerified()
        );

        // 5 — Envia e-mail de verificação se necessário
        if (!command.autoConfirmEmail()) {
            String token = UUID.randomUUID().toString();
            verificationTokenStorePort.store(persisted, token);

            log.debug(
                    "[RegisterUserService] - [register] -> Token de verificação criado userId={} tokenMask={}",
                    persisted.id().value(), maskToken(token)
            );

            sendVerificationEmailPort.send(persisted, token);

            log.debug(
                    "[RegisterUserService] - [register] -> Email de verificação enviado userId={} email={}",
                    persisted.id().value(), persisted.email().value()
            );
        }

        // 6 — Evento de domínio
        publishAuthEventPort.publish(new UserRegisteredEvent(persisted));

        log.debug(
                "[RegisterUserService] - [register] -> Evento UserRegisteredEvent publicado userId={}",
                persisted.id().value()
        );

        return persisted;
    }

    // Helpers
    private String maskToken(String token) {
        if (token == null || token.isBlank()) return "***";
        return token.length() > 10
                ? token.substring(0, 10) + "..."
                : "***";
    }
}
