package br.com.ecofy.auth.core.port.in;

import br.com.ecofy.auth.core.domain.AuthUser;

import java.util.List;

public interface RegisterUserUseCase {

    AuthUser register(RegisterUserCommand command);

    record RegisterUserCommand(

            String email,

            String rawPassword,

            String firstName,

            String lastName,

            String locale,

            boolean autoConfirmEmail, // para ambientes internos/test

            List<String> roles

    ) { }

}
