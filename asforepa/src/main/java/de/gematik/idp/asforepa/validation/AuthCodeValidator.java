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
import de.gematik.idp.token.IdpJwe;
import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import java.util.Set;

public class AuthCodeValidator implements ConstraintValidator<ValidateAuthCode, String> {

  @Override
  public boolean isValid(final String authCode, final ConstraintValidatorContext cxt) {
    if (!Base64UrlValidator.isBase64URL(authCode)) {
      cxt.disableDefaultConstraintViolation();
      cxt.buildConstraintViolationWithTemplate("auth code doesn't match base64url pattern")
          .addConstraintViolation();
      return false;
    }
    return hasCorrectHeaderClaims(new IdpJwe(authCode));
  }

  private static boolean hasCorrectHeaderClaims(final IdpJwe authCode) {
    final boolean hasCorrectClaims;
    try {
      hasCorrectClaims =
          authCode
              .getHeaderClaims()
              .keySet()
              .containsAll(
                  Set.of(
                      ClaimName.ALGORITHM.getJoseName(),
                      ClaimName.ENCRYPTION_ALGORITHM.getJoseName(),
                      ClaimName.CONTENT_TYPE.getJoseName(),
                      ClaimName.EXPIRES_AT.getJoseName()));
    } catch (final IdpJoseException e) {
      return false;
    }
    return hasCorrectClaims;
  }
}
