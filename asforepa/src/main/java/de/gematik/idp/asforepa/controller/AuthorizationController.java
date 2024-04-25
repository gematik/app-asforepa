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
import static de.gematik.idp.asforepa.AsEpaConstants.NONCE_ENDPOINT;
import static de.gematik.idp.asforepa.AsEpaConstants.NONCE_STR_LEN;
import static de.gematik.idp.asforepa.AsEpaConstants.VAU_NP_STR_LEN;
import static de.gematik.idp.field.ClientUtilities.generateCodeChallenge;
import static de.gematik.idp.field.ClientUtilities.generateCodeVerifier;

import de.gematik.idp.asforepa.configuration.AsForEpaConfiguration;
import de.gematik.idp.asforepa.data.AuthCodeRequest;
import de.gematik.idp.asforepa.data.NonceResponse;
import de.gematik.idp.asforepa.exceptions.AsEpaException;
import de.gematik.idp.crypto.Nonce;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import java.net.URISyntaxException;
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
import org.springframework.web.bind.annotation.RestController;

@RestController
@Validated
@RequiredArgsConstructor
@Slf4j
public class AuthorizationController {

  private final AsForEpaConfiguration asForEpaConfiguration;

  @GetMapping(value = NONCE_ENDPOINT)
  public NonceResponse getNonce() {
    final String nonceForAttestation = Nonce.getNonceAsHex(NONCE_STR_LEN);
    return new NonceResponse(nonceForAttestation);
  }

  @GetMapping(value = AUTHZ_REQUEST_SC_ENDPOINT)
  public void getAuthzRequestSc(final HttpServletResponse respMsgNr3) {

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
  public String sendAuthCodeSc(@Valid @RequestBody final AuthCodeRequest authCodeRequest) {
    final String vauNp = Nonce.getNonceAsHex(VAU_NP_STR_LEN);
    return vauNp;
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
}
