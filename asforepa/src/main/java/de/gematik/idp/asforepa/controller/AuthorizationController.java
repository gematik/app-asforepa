/*
 *  Copyright 2024 gematik GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package de.gematik.idp.asforepa.controller;

import static de.gematik.idp.asforepa.AsEpaConstants.AUTHZ_REQUEST_SC_ENDPOINT;
import static de.gematik.idp.asforepa.AsEpaConstants.AUTH_CODE_ENDPOINT;
import static de.gematik.idp.asforepa.AsEpaConstants.CODE_CHALLENGE_METHOD;
import static de.gematik.idp.asforepa.AsEpaConstants.MAX_AUTH_SESSION_AMOUNT;
import static de.gematik.idp.asforepa.AsEpaConstants.NONCE_ENDPOINT;
import static de.gematik.idp.asforepa.AsEpaConstants.NONCE_STR_LEN;
import static de.gematik.idp.asforepa.AsEpaConstants.REQUEST_URI_TTL_SECS;
import static de.gematik.idp.asforepa.AsEpaConstants.VAU_NP_STR_LEN;
import static de.gematik.idp.asforepa.AsEpaConstants.X_USERAGENT;
import static de.gematik.idp.field.ClientUtilities.generateCodeChallenge;
import static de.gematik.idp.field.ClientUtilities.generateCodeVerifier;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import de.gematik.idp.asforepa.configuration.AsForEpaConfiguration;
import de.gematik.idp.asforepa.data.AsEpaErrorCode;
import de.gematik.idp.asforepa.data.AuthCodeRequest;
import de.gematik.idp.asforepa.data.AuthorizationResponse;
import de.gematik.idp.asforepa.data.NonceResponse;
import de.gematik.idp.asforepa.data.UserAgentHeader;
import de.gematik.idp.asforepa.exceptions.AsEpaException;
import de.gematik.idp.crypto.Nonce;
import de.gematik.idp.token.JsonWebToken;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import java.io.Serial;
import java.net.URISyntaxException;
import java.time.ZonedDateTime;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.http.client.utils.URIBuilder;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

@RestController
@Validated
@RequiredArgsConstructor
@Slf4j
public class AuthorizationController {

  private final AsForEpaConfiguration asForEpaConfiguration;

  private final Map<String, ZonedDateTime> authSessions =
      Collections.synchronizedMap(
          new LinkedHashMap<>() {
            @Serial private static final long serialVersionUID = -800086030628953996L;

            @Override
            protected boolean removeEldestEntry(final Entry<String, ZonedDateTime> eldest) {
              return size() > MAX_AUTH_SESSION_AMOUNT;
            }
          });

  @GetMapping(value = NONCE_ENDPOINT)
  public NonceResponse getNonce(
      @Valid @RequestHeader(name = X_USERAGENT) final UserAgentHeader userAgent) {
    final String nonceForAttestation = Nonce.getNonceAsHex(NONCE_STR_LEN);
    authSessions.put(nonceForAttestation, ZonedDateTime.now().plusSeconds(REQUEST_URI_TTL_SECS));
    log.info(
        "Stored AuthSession under nonce {}:\n {}",
        nonceForAttestation,
        authSessions.get(nonceForAttestation));
    return new NonceResponse(nonceForAttestation);
  }

  @GetMapping(value = AUTHZ_REQUEST_SC_ENDPOINT)
  public void getAuthzRequestSc(
      @Valid @RequestHeader(name = X_USERAGENT) final UserAgentHeader userAgent,
      final HttpServletResponse respMsgNr3) {

    respMsgNr3.setStatus(HttpStatus.FOUND.value());

    final String nonce = Nonce.getNonceAsBase64UrlEncodedString(8);
    final String state = Nonce.getNonceAsBase64UrlEncodedString(8);
    final String epaAuthServerCodeVerifier = generateCodeVerifier(); // top secret
    final String epaAuthServerCodeChallenge = generateCodeChallenge(epaAuthServerCodeVerifier);
    final String location =
        createLocationForAuthzResponseSc(
            asForEpaConfiguration.getIdpDienstUrl(),
            asForEpaConfiguration.getRedirectUri(),
            asForEpaConfiguration.getClientId(),
            state,
            nonce,
            epaAuthServerCodeChallenge,
            asForEpaConfiguration.getScopes());
    respMsgNr3.setHeader(HttpHeaders.LOCATION, location);
  }

  @PostMapping(
      value = AUTH_CODE_ENDPOINT,
      consumes = "application/json",
      produces = "application/json")
  public AuthorizationResponse sendAuthCodeSc(
      @Valid @RequestHeader(name = X_USERAGENT) final UserAgentHeader userAgent,
      @Valid @RequestBody final AuthCodeRequest authCodeRequest) {
    final String noncePayload = getNonceFromClientAttest(authCodeRequest.getClientAttest());
    validateNonce(noncePayload);
    authSessions.remove(noncePayload);
    return new AuthorizationResponse(Nonce.getNonceAsHex(VAU_NP_STR_LEN));
  }

  private String createLocationForAuthzResponseSc(
      final String idpEndpoint,
      final String redirectUri,
      final String clientId,
      final String state,
      final String nonce,
      final String codeChallenge,
      final Set<String> scopes) {

    try {
      final URIBuilder redirectUriBuilder = new URIBuilder(idpEndpoint);
      redirectUriBuilder
          .addParameter("redirect_uri", redirectUri)
          .addParameter("client_id", clientId)
          .addParameter("state", state)
          .addParameter("nonce", nonce)
          .addParameter("code_challenge", codeChallenge)
          .addParameter("code_challenge_method", CODE_CHALLENGE_METHOD)
          .addParameter("scope", String.join(" ", scopes))
          .addParameter("response_type", "code");
      return redirectUriBuilder.build().toString();
    } catch (final URISyntaxException e) {
      throw new AsEpaException(e);
    }
  }

  private void validateNonce(final String nonce) {
    if (!authSessions.containsKey(nonce)) {
      throw new AsEpaException(
          AsEpaErrorCode.STATUS_MISMATCH, "invalid or outdated nonce", HttpStatus.CONFLICT);
    } /* else if (authSessions.get(nonce).compareTo(ZonedDateTime.now()) < 0) {
        throw new AsEpaException(
            Oauth2ErrorCode.INVALID_REQUEST, "session expired", HttpStatus.BAD_REQUEST);
      }*/
  }

  private String getNonceFromClientAttest(final String clientAttest) {
    final JsonObject payload =
        JsonParser.parseString(new JsonWebToken(clientAttest).getPayloadDecoded())
            .getAsJsonObject();
    final JsonElement nonceFromClientAttest = payload.get("nonce");
    if (nonceFromClientAttest.isJsonNull()) {
      throw new AsEpaException(
          AsEpaErrorCode.STATUS_MISMATCH, "missing nonce in client attest", HttpStatus.CONFLICT);
    }
    return payload.get("nonce").getAsString();
  }
}
