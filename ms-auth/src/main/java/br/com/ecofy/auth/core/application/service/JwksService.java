package br.com.ecofy.auth.core.application.service;

import br.com.ecofy.auth.core.domain.JwkKey;
import br.com.ecofy.auth.core.port.in.GetJwksUseCase;
import br.com.ecofy.auth.core.port.out.JwksRepositoryPort;
import lombok.extern.slf4j.Slf4j;

import java.util.*;

/**
 * Serviço responsável por montar o JWKS exposto em:
 *      /.well-known/jwks.json
 * Esta implementação trata apenas metadados mínimos (kid, alg, use),
 * mas está preparada para incluir parâmetros completos RSA (n, e)
 * assim que o adapter de persistência fornecer esses valores.
 */
@Slf4j
public class JwksService implements GetJwksUseCase {

    private final JwksRepositoryPort jwksRepositoryPort;

    public JwksService(JwksRepositoryPort jwksRepositoryPort) {
        this.jwksRepositoryPort =
                Objects.requireNonNull(jwksRepositoryPort, "jwksRepositoryPort must not be null");
    }

    @Override
    public Map<String, Object> getJwks() {
        log.debug("[JwksService] - [getJwks] -> Buscando chaves ativas…");

        List<JwkKey> keys = jwksRepositoryPort.findActiveSigningKeys();

        if (keys.isEmpty()) {
            log.warn("[JwksService] - [getJwks] -> Nenhuma JWK ativa encontrada.");
        } else {
            log.debug(
                    "[JwksService] - [getJwks] -> {} chave(s) ativa(s) encontrada(s).",
                    keys.size()
            );
        }

        // Mapeia JwkKey -> JSON format JWKS entries
        List<Map<String, Object>> jwkList = keys.stream()
                .map(this::convertToJwkEntry)
                .toList();

        Map<String, Object> response = Map.of("keys", jwkList);

        log.debug(
                "[JwksService] - [getJwks] -> JWKS gerado com sucesso totalKeys={}",
                jwkList.size()
        );

        return response;
    }

    /**
     * Converte nosso JwkKey do domínio para o formato JWKS.
     * Importante: por agora só devolvemos informações mínimas.
     * Quando o adapter fornecer "n" e "e" (partes públicas RSA),
     * basta adicionar aqui:
     *      m.put("n", rsaModulusBase64Url);
     *      m.put("e", rsaExponentBase64Url);
     */
    private Map<String, Object> convertToJwkEntry(JwkKey key) {
        Map<String, Object> m = new LinkedHashMap<>();

        m.put("kid", key.keyId());
        m.put("alg", key.algorithm());
        m.put("use", key.use());
        m.put("kty", "RSA");

        log.debug(
                "[JwksService] - [convertToJwkEntry] -> Convertendo keyId={} alg={} use={}",
                key.keyId(), key.algorithm(), key.use()
        );

        // futuro: extrair modulus/base64url do PEM e incluir:
        // m.put("n", key.rsaModulus());
        // m.put("e", key.rsaExponent());

        return m;
    }
}
