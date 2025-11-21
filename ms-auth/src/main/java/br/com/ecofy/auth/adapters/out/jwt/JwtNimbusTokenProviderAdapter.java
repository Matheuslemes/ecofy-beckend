package br.com.ecofy.auth.adapters.out.jwt;

import br.com.ecofy.auth.config.JwtProperties;
import br.com.ecofy.auth.core.domain.JwtToken;
import br.com.ecofy.auth.core.domain.enums.TokenType;
import br.com.ecofy.auth.core.port.out.JwtTokenProviderPort;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.stereotype.Component;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.text.ParseException;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.Map;
import java.util.Objects;

@Component
@Slf4j
public class JwtNimbusTokenProviderAdapter implements JwtTokenProviderPort {

    private final JwtProperties jwtProperties;
    private final RSAPrivateKey privateKey;
    private final RSAPublicKey publicKey;
    private final JWSSigner signer;
    private final JWSHeader jwsHeader;

    public JwtNimbusTokenProviderAdapter(JwtProperties jwtProperties, ResourceLoader resourceLoader) {
        this.jwtProperties = Objects.requireNonNull(jwtProperties, "jwtProperties must not be null");

        this.privateKey = loadPrivateKey(resourceLoader, jwtProperties.getPrivateKeyLocation());
        this.publicKey  = loadPublicKey(resourceLoader, jwtProperties.getPublicKeyLocation());

        this.signer = createSigner(privateKey);

        this.jwsHeader = new JWSHeader.Builder(JWSAlgorithm.RS256)
                .keyID(jwtProperties.getKeyId())
                .type(JOSEObjectType.JWT)
                .build();

        log.info(
                "[JwtNimbusTokenProviderAdapter] - [constructor] -> Chaves JWT carregadas com sucesso keyId={}",
                jwtProperties.getKeyId()
        );
    }

    // ======================================================================
    // ACCESS / REFRESH (contrato atual da porta)
    // ======================================================================

    @Override
    public JwtToken generateAccessToken(String subject, Map<String, Object> claims, long ttlSeconds) {
        return generateToken(subject, claims, ttlSeconds, TokenType.ACCESS);
    }

    @Override
    public JwtToken generateRefreshToken(String subject, Map<String, Object> claims, long ttlSeconds) {
        return generateToken(subject, claims, ttlSeconds, TokenType.REFRESH);
    }

    // ======================================================================
    // VERIFICATION / PASSWORD_RESET (uso dos enums restantes)
    // ======================================================================

    /**
     * Gera um JWT específico para fluxo de verificação de e-mail.
     * Usa TokenType.VERIFICATION.
     *
     * OBS: este método ainda não faz parte do contrato da porta,
     * mas pode ser exposto futuramente em JwtTokenProviderPort.
     */
    public JwtToken generateVerificationToken(String subject,
                                              Map<String, Object> claims,
                                              long ttlSeconds) {

        log.debug(
                "[JwtNimbusTokenProviderAdapter] - [generateVerificationToken] -> Gerando token de verificação subject={} ttlSeconds={}",
                subject, ttlSeconds
        );

        // Você pode marcar o propósito como claim adicional, se quiser
        if (claims != null) {
            claims.putIfAbsent("purpose", "EMAIL_VERIFICATION");
        }

        return generateToken(subject, claims, ttlSeconds, TokenType.VERIFICATION);
    }

    /**
     * Gera um JWT específico para fluxo de reset de senha.
     * Usa TokenType.PASSWORD_RESET.
     */
    public JwtToken generatePasswordResetToken(String subject,
                                               Map<String, Object> claims,
                                               long ttlSeconds) {

        log.debug(
                "[JwtNimbusTokenProviderAdapter] - [generatePasswordResetToken] -> Gerando token de reset de senha subject={} ttlSeconds={}",
                subject, ttlSeconds
        );

        if (claims != null) {
            claims.putIfAbsent("purpose", "PASSWORD_RESET");
        }

        return generateToken(subject, claims, ttlSeconds, TokenType.PASSWORD_RESET);
    }

    // Núcleo de geração
    private JwtToken generateToken(String subject,
                                   Map<String, Object> claims,
                                   long ttlSeconds,
                                   TokenType type) {

        Objects.requireNonNull(subject, "subject must not be null");
        Objects.requireNonNull(type, "type must not be null");
        // claims pode ser null; tratamos abaixo

        Instant now = Instant.now();
        Instant exp = now.plusSeconds(ttlSeconds);

        log.debug(
                "[JwtNimbusTokenProviderAdapter] - [generateToken] -> Gerando token type={} subject={} ttlSeconds={}",
                type, subject, ttlSeconds
        );

        var builder = new JWTClaimsSet.Builder()
                .subject(subject)
                .issuer(jwtProperties.getIssuer())
                .audience(jwtProperties.getAudience())
                .issueTime(Date.from(now))
                .expirationTime(Date.from(exp))
                .notBeforeTime(Date.from(now.minusSeconds(jwtProperties.getClockSkewSeconds())))
                // tipagem lógica do token no claim: ACCESS, REFRESH, VERIFICATION, PASSWORD_RESET
                .claim("typ", type.name());

        if (claims != null) {
            claims.forEach(builder::claim);
        }

        SignedJWT signedJWT = new SignedJWT(jwsHeader, builder.build());
        try {
            signedJWT.sign(signer);
        } catch (JOSEException e) {
            log.error(
                    "[JwtNimbusTokenProviderAdapter] - [generateToken] -> Erro ao assinar JWT subject={} type={} error={}",
                    subject, type, e.getMessage(), e
            );
            throw new IllegalStateException("Error signing JWT", e);
        }

        String serialized = signedJWT.serialize();

        log.debug(
                "[JwtNimbusTokenProviderAdapter] - [generateToken] -> Token gerado com sucesso type={} subject={}",
                type, subject
        );

        return new JwtToken(serialized, exp, type);
    }

    // Validação / parsing
    @Override
    public boolean isValid(String token) {
        try {
            SignedJWT jwt = SignedJWT.parse(token);
            var claimsSet = jwt.getJWTClaimsSet();

            Date exp = claimsSet.getExpirationTime();
            TokenType type = resolveTokenType(claimsSet);

            boolean valid = exp != null && exp.after(new Date());

            log.debug(
                    "[JwtNimbusTokenProviderAdapter] - [isValid] -> Validação de expiração valid={} exp={} type={}",
                    valid, exp, type
            );

            // Assinatura é validada no Resource Server (JwtDecoder).
            return valid;
        } catch (Exception e) {
            log.warn(
                    "[JwtNimbusTokenProviderAdapter] - [isValid] -> Token inválido error={}",
                    e.getMessage()
            );
            return false;
        }
    }

    @Override
    public Map<String, Object> parseClaims(String token) {
        try {
            SignedJWT jwt = SignedJWT.parse(token);
            var claimsSet = jwt.getJWTClaimsSet();
            var claims = claimsSet.getClaims();

            TokenType type = resolveTokenType(claimsSet);

            log.debug(
                    "[JwtNimbusTokenProviderAdapter] - [parseClaims] -> Claims parseadas com sucesso subject={} type={}",
                    claimsSet.getSubject(), type
            );

            return claims;
        } catch (ParseException e) {
            log.error(
                    "[JwtNimbusTokenProviderAdapter] - [parseClaims] -> Token inválido error={}",
                    e.getMessage(), e
            );
            throw new IllegalArgumentException("Invalid JWT", e);
        }
    }

    /**
     * Resolve o TokenType a partir do claim "typ".
     * Usa todos os valores do enum TokenType: ACCESS, REFRESH, VERIFICATION, PASSWORD_RESET.
     */
    private TokenType resolveTokenType(JWTClaimsSet claimsSet) {
        Object raw = claimsSet.getClaim("typ");
        if (raw == null) {
            return null;
        }
        try {
            return TokenType.valueOf(raw.toString());
        } catch (IllegalArgumentException ex) {
            log.warn(
                    "[JwtNimbusTokenProviderAdapter] - [resolveTokenType] -> Valor de typ desconhecido typ={}",
                    raw
            );
            return null;
        }
    }

    // Chaves / JWK
    private JWSSigner createSigner(RSAPrivateKey privateKey) {
        log.debug("[JwtNimbusTokenProviderAdapter] - [createSigner] -> Criando RSASSASigner");
        return new RSASSASigner(privateKey);
    }

    private RSAPrivateKey loadPrivateKey(ResourceLoader resourceLoader, String location) {
        Objects.requireNonNull(location, "private key location must not be null");
        log.debug(
                "[JwtNimbusTokenProviderAdapter] - [loadPrivateKey] -> Carregando chave privada location={}",
                location
        );
        try {
            Resource resource = resourceLoader.getResource(location);
            try (InputStream is = resource.getInputStream()) {
                String pem = new String(is.readAllBytes(), StandardCharsets.UTF_8);
                String sanitized = pem
                        .replace("-----BEGIN PRIVATE KEY-----", "")
                        .replace("-----END PRIVATE KEY-----", "")
                        .replaceAll("\\s", "");

                byte[] decoded = Base64.getDecoder().decode(sanitized);
                PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decoded);
                KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                RSAPrivateKey key = (RSAPrivateKey) keyFactory.generatePrivate(keySpec);

                log.debug("[JwtNimbusTokenProviderAdapter] - [loadPrivateKey] -> Chave privada carregada com sucesso");
                return key;
            }
        } catch (Exception e) {
            log.error(
                    "[JwtNimbusTokenProviderAdapter] - [loadPrivateKey] -> Falha ao carregar chave privada location={} error={}",
                    location, e.getMessage(), e
            );
            throw new IllegalStateException("Could not load private key from " + location, e);
        }
    }

    private RSAPublicKey loadPublicKey(ResourceLoader resourceLoader, String location) {
        Objects.requireNonNull(location, "public key location must not be null");
        log.debug(
                "[JwtNimbusTokenProviderAdapter] - [loadPublicKey] -> Carregando chave pública location={}",
                location
        );
        try {
            Resource resource = resourceLoader.getResource(location);
            try (InputStream is = resource.getInputStream()) {
                String pem = new String(is.readAllBytes(), StandardCharsets.UTF_8);
                String sanitized = pem
                        .replace("-----BEGIN PUBLIC KEY-----", "")
                        .replace("-----END PUBLIC KEY-----", "")
                        .replaceAll("\\s", "");

                byte[] decoded = Base64.getDecoder().decode(sanitized);
                X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decoded);
                KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                RSAPublicKey key = (RSAPublicKey) keyFactory.generatePublic(keySpec);

                log.debug("[JwtNimbusTokenProviderAdapter] - [loadPublicKey] -> Chave pública carregada com sucesso");
                return key;
            }
        } catch (Exception e) {
            log.error(
                    "[JwtNimbusTokenProviderAdapter] - [loadPublicKey] -> Falha ao carregar chave pública location={} error={}",
                    location, e.getMessage(), e
            );
            throw new IllegalStateException("Could not load public key from " + location, e);
        }
    }

    /**
     * Monta um JWK (JSON Web Key) a partir da chave pública carregada.
     * Normalmente usado pelo serviço que expõe o endpoint /.well-known/jwks.json.
     */
    public RSAKey toRsaJwk() {
        log.debug(
                "[JwtNimbusTokenProviderAdapter] - [toRsaJwk] -> Gerando JWK keyId={}",
                jwtProperties.getKeyId()
        );
        return new RSAKey.Builder(publicKey)
                .keyID(jwtProperties.getKeyId())
                .algorithm(JWSAlgorithm.RS256)
                .build();
    }
}
