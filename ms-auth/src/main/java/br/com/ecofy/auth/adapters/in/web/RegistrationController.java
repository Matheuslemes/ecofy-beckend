package br.com.ecofy.auth.adapters.in.web;

import br.com.ecofy.auth.adapters.in.web.dto.ConfirmEmailRequest;
import br.com.ecofy.auth.adapters.in.web.dto.RegisterUserRequest;
import br.com.ecofy.auth.adapters.in.web.dto.UserResponse;
import br.com.ecofy.auth.core.port.in.ConfirmEmailUseCase;
import br.com.ecofy.auth.core.port.in.RegisterUserUseCase;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import java.net.URI;
import java.util.List;

@RestController
@RequestMapping(path = "/api/register", produces = MediaType.APPLICATION_JSON_VALUE)
@Validated
@Tag(name = "Registration", description = "Registro de novos usuários e confirmação de e-mail")
@Slf4j
@RequiredArgsConstructor
public class RegistrationController {

    private final RegisterUserUseCase registerUserUseCase;
    private final ConfirmEmailUseCase confirmEmailUseCase;


    @Operation(
            summary = "Registra um novo usuário",
            description = """
                    Cria um novo usuário no ms-auth.
                    Se a confirmação de e-mail estiver habilitada, envia e-mail com token de verificação.
                    """
    )
    @ApiResponses({
            @ApiResponse(responseCode = "201", description = "Usuário registrado com sucesso",
                    content = @Content(schema = @Schema(implementation = UserResponse.class))),
            @ApiResponse(responseCode = "400", description = "Dados inválidos ou e-mail já registrado"),
            @ApiResponse(responseCode = "500", description = "Erro interno ao registrar usuário")
    })
    @PostMapping(consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<UserResponse> register(@Valid @RequestBody RegisterUserRequest request) {

        log.debug("[RegistrationController] - [register] -> Registrando usuário email={}", request.email());

        var cmd = new RegisterUserUseCase.RegisterUserCommand(
                request.email(),
                request.password(),
                request.firstName(),
                request.lastName(),
                request.locale() != null ? request.locale() : "pt-BR",
                false,
                List.of("AUTH_USER") // em prod, normalmente não auto-confirma
        );

        var user = registerUserUseCase.register(cmd);

        log.debug("[RegistrationController] - [register] -> Usuário registrado com sucesso userId={} email={}",
                user.id().value(), user.email().value());

        UserResponse body = UserMapper.toResponse(user);

        // Location padrão apontando para o endpoint de perfil
        URI location = ServletUriComponentsBuilder
                .fromCurrentContextPath()
                .path("/api/user/me")
                .build()
                .toUri();

        return ResponseEntity
                .created(location)
                .body(body);
    }

    @Operation(
            summary = "Confirma o e-mail de um usuário",
            description = """
                    Consome o token de verificação enviado por e-mail e ativa o usuário.
                    """
    )
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "E-mail confirmado com sucesso",
                    content = @Content(schema = @Schema(implementation = UserResponse.class))),
            @ApiResponse(responseCode = "400", description = "Token inválido ou já utilizado"),
            @ApiResponse(responseCode = "410", description = "Token expirado"),
            @ApiResponse(responseCode = "500", description = "Erro interno ao confirmar e-mail")
    })
    @PostMapping(path = "/confirm-email", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<UserResponse> confirmEmail(@Valid @RequestBody ConfirmEmailRequest request) {

        log.debug("[RegistrationController] - [confirmEmail] -> Confirmando e-mail token={}", request.token());

        var cmd = new ConfirmEmailUseCase.ConfirmEmailCommand(request.token());
        var user = confirmEmailUseCase.confirm(cmd);

        log.debug("[RegistrationController] - [confirmEmail] -> E-mail confirmado com sucesso userId={} email={}",
                user.id().value(), user.email().value());

        return ResponseEntity.ok(UserMapper.toResponse(user));
    }
}
