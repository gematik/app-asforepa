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
import de.gematik.idp.token.JsonWebToken;
import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import java.security.cert.X509Certificate;
import java.util.Optional;

public class ClientAttestValidator implements ConstraintValidator<ValidateClientAttest, String> {

  @Override
  public boolean isValid(final String clientAttest, final ConstraintValidatorContext cxt) {
    return isValidClientAttest(new JsonWebToken(clientAttest));
  }

  private static boolean isValidClientAttest(final JsonWebToken clientAttest) {
    try {
      final Optional<X509Certificate> smcbCertificate =
          clientAttest.getClientCertificateFromHeader();
      if (smcbCertificate.isEmpty()) {
        return false;
      }
      clientAttest.verify(smcbCertificate.get().getPublicKey());
    } catch (final IdpJoseException e) {
      return false;
    }
    return true;
  }
}
