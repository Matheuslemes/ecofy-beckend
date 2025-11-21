package br.com.ecofy.auth.core.application.service;

import br.com.ecofy.auth.core.domain.AuthUser;
import br.com.ecofy.auth.core.domain.event.PasswordResetRequestedEvent;
import br.com.ecofy.auth.core.domain.valueobject.EmailAddress;
import br.com.ecofy.auth.core.domain.valueobject.PasswordHash;
import br.com.ecofy.auth.core.port.in.RequestPasswordResetUseCase;
import br.com.ecofy.auth.core.port.in.ResetPasswordUseCase;
import br.com.ecofy.auth.core.port.out.*;
import lombok.extern.slf4j.Slf4j;

import java.util.Objects;
import java.util.UUID;

/**
 * Serviço responsável pelo fluxo completo de:
 *  1. Solicitação de reset de senha
 *  2. Consumo do token e definição da nova senha
 * Princípios aplicados:
 *  - Logs estruturados (sem expor tokens ou dados sensíveis)
 *  - Fail-fast em dependências nulas
 *  - Eventos de domínio publicados nos momentos adequados
 *  - Tokens armazenados apenas em store especializado
 */
@Slf4j
public class PasswordResetService implements RequestPasswordResetUseCase, ResetPasswordUseCase {

    private final LoadAuthUserByEmailPort loadAuthUserByEmailPort;
    private final PasswordResetTokenStorePort passwordResetTokenStorePort;
    private final SendResetPasswordEmailPort sendResetPasswordEmailPort;
    private final SaveAuthUserPort saveAuthUserPort;
    private final PasswordHashingPort passwordHashingPort;
    private final PublishAuthEventPort publishAuthEventPort;

    public PasswordResetService(LoadAuthUserByEmailPort loadAuthUserByEmailPort,
                                PasswordResetTokenStorePort passwordResetTokenStorePort,
                                SendResetPasswordEmailPort sendResetPasswordEmailPort,
                                SaveAuthUserPort saveAuthUserPort,
                                PasswordHashingPort passwordHashingPort,
                                PublishAuthEventPort publishAuthEventPort) {

        this.loadAuthUserByEmailPort =
                Objects.requireNonNull(loadAuthUserByEmailPort, "loadAuthUserByEmailPort must not be null");
        this.passwordResetTokenStorePort =
                Objects.requireNonNull(passwordResetTokenStorePort, "passwordResetTokenStorePort must not be null");
        this.sendResetPasswordEmailPort =
                Objects.requireNonNull(sendResetPasswordEmailPort, "sendResetPasswordEmailPort must not be null");
        this.saveAuthUserPort =
                Objects.requireNonNull(saveAuthUserPort, "saveAuthUserPort must not be null");
        this.passwordHashingPort =
                Objects.requireNonNull(passwordHashingPort, "passwordHashingPort must not be null");
        this.publishAuthEventPort =
                Objects.requireNonNull(publishAuthEventPort, "publishAuthEventPort must not be null");
    }

    // REQUEST RESET
    @Override
    public void requestReset(RequestPasswordResetCommand command) {
        Objects.requireNonNull(command, "command must not be null");
        EmailAddress email = new EmailAddress(command.email());

        log.debug(
                "[PasswordResetService] - [requestReset] -> Solicitando reset para email={}",
                email.value()
        );

        AuthUser user = loadAuthUserByEmailPort
                .loadByEmail(email)
                .orElseThrow(() -> {
                    log.warn(
                            "[PasswordResetService] - [requestReset] -> Usuário não encontrado email={}",
                            email.value()
                    );
                    return new IllegalArgumentException("User not found");
                });

        String resetToken = UUID.randomUUID().toString();
        String masked = maskToken(resetToken);

        log.debug(
                "[PasswordResetService] - [requestReset] -> Token gerado userId={} token={}",
                user.id().value(), masked
        );

        passwordResetTokenStorePort.store(user, resetToken);
        sendResetPasswordEmailPort.sendReset(user, resetToken);

        log.debug(
                "[PasswordResetService] - [requestReset] -> E-mail de reset enviado userId={} email={}",
                user.id().value(), user.email().value()
        );

        publishAuthEventPort.publish(new PasswordResetRequestedEvent(user, resetToken));

        log.debug(
                "[PasswordResetService] - [requestReset] -> Evento PasswordResetRequestedEvent publicado userId={}",
                user.id().value()
        );
    }

    // RESET PASSWORD
    @Override
    public void resetPassword(ResetPasswordCommand command) {
        Objects.requireNonNull(command, "command must not be null");

        String maskedToken = maskToken(command.resetToken());

        log.debug(
                "[PasswordResetService] - [resetPassword] -> Validando token para redefinição token={}",
                maskedToken
        );

        AuthUser user = passwordResetTokenStorePort
                .consume(command.resetToken())
                .orElseThrow(() -> {
                    log.warn(
                            "[PasswordResetService] - [resetPassword] -> Token inválido ou expirado token={}",
                            maskedToken
                    );
                    return new IllegalArgumentException("Invalid or expired reset token");
                });

        log.debug(
                "[PasswordResetService] - [resetPassword] -> Token válido userId={}",
                user.id().value()
        );

        PasswordHash newHash = passwordHashingPort.hash(command.newPassword());

        user.changePassword(newHash);
        saveAuthUserPort.save(user);

        log.debug(
                "[PasswordResetService] - [resetPassword] -> Senha redefinida com sucesso userId={}",
                user.id().value()
        );
    }

    // =====================================================================
    // Utils
    // =====================================================================

    private String maskToken(String token) {
        if (token == null || token.isBlank()) return "***";
        return token.length() > 10 ? token.substring(0, 10) + "..." : "***";
    }
}
