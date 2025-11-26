package br.com.ecofy.auth.adapters.in.web;

import br.com.ecofy.auth.adapters.in.web.dto.PasswordResetConfirmRequest;
import br.com.ecofy.auth.adapters.in.web.dto.PasswordResetRequest;
import br.com.ecofy.auth.core.port.in.RequestPasswordResetUseCase;
import br.com.ecofy.auth.core.port.in.ResetPasswordUseCase;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(path = "/api/password", produces = MediaType.APPLICATION_JSON_VALUE)
@Validated
@Tag(name = "Password", description = "Fluxo de recuperação e redefinição de senha")
@Slf4j
@RequiredArgsConstructor
public class PasswordController {

    private final RequestPasswordResetUseCase requestPasswordResetUseCase;
    private final ResetPasswordUseCase resetPasswordUseCase;

    @Operation(
            summary = "Solicita redefinição de senha",
            description = """
                    Envia um e-mail com link/token de redefinição de senha para o usuário,
                    caso o e-mail exista na base.
                    Sempre retorna 202 para não expor se o e-mail está cadastrado.
                    """
    )
    @ApiResponses({
            @ApiResponse(responseCode = "202", description = "Solicitação de reset aceita"),
            @ApiResponse(responseCode = "400", description = "Requisição inválida"),
            @ApiResponse(responseCode = "500", description = "Erro interno ao processar solicitação")
    })
    @PostMapping(path = "/reset-request", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Void> requestReset(@Valid @RequestBody PasswordResetRequest request) {

        // Não logar senha (não vem aqui) e evitar logar dados sensíveis demais
        log.debug("[PasswordController] - [requestReset] -> Solicitando reset de senha email={}", request.email());

        requestPasswordResetUseCase.requestReset(
                new RequestPasswordResetUseCase.RequestPasswordResetCommand(request.email())
        );

        log.debug("[PasswordController] - [requestReset] -> Solicitação de reset processada email={}", request.email());

        return ResponseEntity.accepted().build();
    }

    @Operation(
            summary = "Confirma redefinição de senha",
            description = """
                    Consome o token de redefinição de senha e define uma nova senha para o usuário.
                    Se o token estiver inválido ou expirado, o caso é tratado na camada de aplicação.
                    """
    )
    @ApiResponses({
            @ApiResponse(responseCode = "204", description = "Senha redefinida com sucesso"),
            @ApiResponse(responseCode = "400", description = "Token inválido ou requisição inválida"),
            @ApiResponse(responseCode = "410", description = "Token expirado"),
            @ApiResponse(responseCode = "500", description = "Erro interno ao redefinir senha")
    })
    @PostMapping(path = "/reset-confirm", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Void> confirmReset(@Valid @RequestBody PasswordResetConfirmRequest request) {

        log.debug("[PasswordController] - [confirmReset] -> Confirmando reset de senha token={}", request.token());

        resetPasswordUseCase.resetPassword(
                new ResetPasswordUseCase.ResetPasswordCommand(
                        request.token(),
                        request.newPassword()
                )
        );

        log.debug("[PasswordController] - [confirmReset] -> Reset de senha concluído token={}", request.token());

        return ResponseEntity.noContent().build();
    }
}
