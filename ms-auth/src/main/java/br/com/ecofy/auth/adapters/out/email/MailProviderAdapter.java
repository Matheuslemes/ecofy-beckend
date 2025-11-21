package br.com.ecofy.auth.adapters.out.email;

import br.com.ecofy.auth.config.MailConfig;
import br.com.ecofy.auth.core.domain.AuthUser;
import br.com.ecofy.auth.core.port.out.SendResetPasswordEmailPort;
import br.com.ecofy.auth.core.port.out.SendVerificationEmailPort;
import lombok.extern.slf4j.Slf4j;
import org.springframework.mail.MailException;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.Objects;

@Component
@Slf4j
public class MailProviderAdapter implements SendVerificationEmailPort, SendResetPasswordEmailPort {

    private final JavaMailSender mailSender;
    private final MailConfig.EcofyMailProperties props;

    public MailProviderAdapter(JavaMailSender mailSender, MailConfig.EcofyMailProperties props) {
        this.mailSender = Objects.requireNonNull(mailSender, "mailSender must not be null");
        this.props = Objects.requireNonNull(props, "props must not be null");
    }

    @Override
    public void send(AuthUser user, String verificationToken) {
        Objects.requireNonNull(user, "user must not be null");
        Objects.requireNonNull(verificationToken, "verificationToken must not be null");

        String link = buildVerificationLink(verificationToken);

        log.debug(
                "[MailProviderAdapter] - [send] -> Enviando e-mail de verificação userId={} email={}",
                user.id().value(), user.email().value()
        );

        SimpleMailMessage message = baseMessage(user);
        message.setSubject("Confirme seu e-mail – EcoFy");
        message.setText("""
                Olá %s,

                Seja bem-vindo à EcoFy!

                Para ativar sua conta, clique no link abaixo:

                %s

                Se você não criou esta conta, ignore esta mensagem.

                Atenciosamente,
                Equipe EcoFy
                """.formatted(user.fullName(), link));

        sendMail(message, "verificação", user);
    }

    @Override
    public void sendReset(AuthUser user, String resetToken) {
        Objects.requireNonNull(user, "user must not be null");
        Objects.requireNonNull(resetToken, "resetToken must not be null");

        String link = buildResetLink(resetToken);

        log.debug(
                "[MailProviderAdapter] - [sendReset] -> Enviando e-mail de reset de senha userId={} email={}",
                user.id().value(), user.email().value()
        );

        SimpleMailMessage message = baseMessage(user);
        message.setSubject("Redefinição de senha – EcoFy");
        message.setText("""
                Olá %s,

                Recebemos uma solicitação para redefinir sua senha na EcoFy.

                Para criar uma nova senha, clique no link abaixo:

                %s

                Se você não solicitou esta redefinição, apenas ignore este e-mail.

                Atenciosamente,
                Equipe EcoFy
                """.formatted(user.fullName(), link));

        sendMail(message, "reset de senha", user);
    }

    // Helpers
    private SimpleMailMessage baseMessage(AuthUser user) {
        String from = Objects.requireNonNullElse(props.getFrom(), "no-reply@ecofy.local");

        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom(from);
        message.setTo(user.email().value());
        return message;
    }

    private String buildVerificationLink(String token) {
        String baseUrl = Objects.requireNonNullElse(
                props.getFrontendBaseUrl(),
                "http://localhost:3000"
        );

        return UriComponentsBuilder
                .fromUriString(baseUrl)
                .path("/auth/confirm-email")
                .queryParam("token", token)
                .build()
                .toUriString();
    }

    private String buildResetLink(String token) {
        String baseUrl = Objects.requireNonNullElse(
                props.getFrontendBaseUrl(),
                "http://localhost:3000"
        );

        return UriComponentsBuilder
                .fromUriString(baseUrl)
                .path("/auth/reset-password")
                .queryParam("token", token)
                .build()
                .toUriString();
    }

    private void sendMail(SimpleMailMessage message, String tipoEmail, AuthUser user) {
        try {
            mailSender.send(message);
            log.debug(
                    "[MailProviderAdapter] - [sendMail] -> E-mail de {} enviado com sucesso email={}",
                    tipoEmail, user.email().value()
            );
        } catch (MailException ex) {
            log.error(
                    "[MailProviderAdapter] - [sendMail] -> Falha ao enviar e-mail de {} email={} error={}",
                    tipoEmail, user.email().value(), ex.getMessage(), ex
            );
            throw new IllegalStateException("Falha ao enviar e-mail de " + tipoEmail, ex);
        }
    }
}
