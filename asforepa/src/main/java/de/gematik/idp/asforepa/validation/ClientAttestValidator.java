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

package de.gematik.idp.asforepa.validation;

import de.gematik.idp.exceptions.IdpJoseException;
import de.gematik.idp.field.ClaimName;
import de.gematik.idp.token.JsonWebToken;
import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import java.util.NoSuchElementException;
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
    return isValidClientAttest(new JsonWebToken(clientAttest));
  }

  private static boolean isValidClientAttest(final JsonWebToken clientAttest) {
    try {
      final String algorithm =
          (String) clientAttest.getHeaderClaim(ClaimName.ALGORITHM).orElseThrow();
      return algorithm.equals(AlgorithmIdentifiers.RSA_PSS_USING_SHA256)
          || algorithm.equals(AlgorithmIdentifiers.ECDSA_USING_P256_CURVE_AND_SHA256);
    } catch (final IdpJoseException | NoSuchElementException e) {
      return false;
    }
  }
}
