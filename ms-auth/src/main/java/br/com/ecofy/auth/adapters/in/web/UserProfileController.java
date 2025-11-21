package br.com.ecofy.auth.adapters.in.web;

import br.com.ecofy.auth.adapters.in.web.dto.UserResponse;
import br.com.ecofy.auth.core.port.in.GetCurrentUserProfileUseCase;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(path = "/api/user", produces = MediaType.APPLICATION_JSON_VALUE)
@Validated
@Tag(name = "User Profile", description = "Consulta de perfil do usuário autenticado")
@Slf4j
public class UserProfileController {

    private final GetCurrentUserProfileUseCase getCurrentUserProfileUseCase;

    public UserProfileController(GetCurrentUserProfileUseCase getCurrentUserProfileUseCase) {
        this.getCurrentUserProfileUseCase = getCurrentUserProfileUseCase;
    }

    @Operation(
            summary = "Retorna o perfil do usuário autenticado",
            description = """
                    Retorna os dados básicos do usuário dono do access token atual.
                    Normalmente consumido pelo frontend (EcoFy Dashboard) logo após o login.
                    """
    )
    @ApiResponses({
            @ApiResponse(
                    responseCode = "200",
                    description = "Perfil retornado com sucesso",
                    content = @Content(schema = @Schema(implementation = UserResponse.class))
            ),
            @ApiResponse(responseCode = "401", description = "Usuário não autenticado ou token inválido"),
            @ApiResponse(responseCode = "500", description = "Erro interno ao buscar perfil")
    })
    @GetMapping("/me")
    public ResponseEntity<UserResponse> me() {
        log.debug("[UserProfileController] - [me] -> Buscando perfil do usuário atual");

        var user = getCurrentUserProfileUseCase.getCurrentUser();

        log.debug("[UserProfileController] - [me] -> Perfil encontrado userId={} email={}",
                user.id().value(), user.email().value());

        return ResponseEntity.ok(UserMapper.toResponse(user));
    }
}
