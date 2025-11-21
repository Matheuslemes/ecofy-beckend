package br.com.ecofy.auth.adapters.in.web.dto;

import jakarta.validation.constraints.NotBlank;

public record LoginRequest(

        @NotBlank
        String clientId,

        // pode ser null em client public
        String clientSecret,

        @NotBlank
        String username,

        @NotBlank
        String password,

        String scope

) { }