/*
 * Copyright (Change Date see Readme), gematik GmbH
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
 *
 * *******
 *
 * For additional notes and disclaimer from gematik and in case of changes by gematik find details in the "Readme" file.
 */

package de.gematik.idp.asforepa.validation;

import de.gematik.idp.exceptions.IdpJoseException;
import de.gematik.idp.field.ClaimName;
import de.gematik.idp.token.JsonWebToken;
import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.NoSuchElementException;
import java.util.Optional;
import org.jose4j.jws.AlgorithmIdentifiers;

public class ClientAttestValidator implements ConstraintValidator<ValidateClientAttest, String> {

  @Override
  public boolean isValid(final String clientAttest, final ConstraintValidatorContext cxt) {
    if (clientAttest == null) {
      cxt.disableDefaultConstraintViolation();
      cxt.buildConstraintViolationWithTemplate("client attest is missing").addConstraintViolation();
      return false;
    }
    if (!Base64UrlValidator.isBase64URL(clientAttest)) {
      cxt.disableDefaultConstraintViolation();
      cxt.buildConstraintViolationWithTemplate("client attest doesn't match base64url pattern")
          .addConstraintViolation();
      return false;
    }
    return isValidClientAttest(new JsonWebToken(clientAttest), cxt);
  }

  private static boolean isValidClientAttest(
      final JsonWebToken clientAttest, final ConstraintValidatorContext cxt) {
    try {
      final String algorithm =
          (String) clientAttest.getHeaderClaim(ClaimName.ALGORITHM).orElseThrow();
      if (!(algorithm.equals(AlgorithmIdentifiers.RSA_PSS_USING_SHA256)
          || algorithm.equals(AlgorithmIdentifiers.ECDSA_USING_P256_CURVE_AND_SHA256))) {
        cxt.disableDefaultConstraintViolation();
        cxt.buildConstraintViolationWithTemplate("client attest uses invalid algorithm")
            .addConstraintViolation();
        return false;
      }
      final int signatureLength =
          Base64.getUrlDecoder().decode(clientAttest.getRawString().split("\\.")[2]).length;
      if ((algorithm.equals(AlgorithmIdentifiers.RSA_PSS_USING_SHA256) && (signatureLength != 256))
          || (algorithm.equals(AlgorithmIdentifiers.ECDSA_USING_P256_CURVE_AND_SHA256)
              && signatureLength != 64)) {
        cxt.disableDefaultConstraintViolation();
        cxt.buildConstraintViolationWithTemplate("client attest has invalid signature length")
            .addConstraintViolation();
        return false;
      }
      if (algorithm.equals(AlgorithmIdentifiers.RSA_PSS_USING_SHA256)) {
        final Optional<X509Certificate> smcbCertificate =
            clientAttest.getClientCertificateFromHeader();
        if (smcbCertificate.isEmpty()) {
          return false;
        }
        try {
          clientAttest.verify(smcbCertificate.get().getPublicKey());
        } catch (final IdpJoseException e) {
          return false;
        }
      }
      return true;
    } catch (final IdpJoseException | NoSuchElementException e) {
      return false;
    }
  }
}
