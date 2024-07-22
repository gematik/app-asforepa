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

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

public class UserAgentValidator implements ConstraintValidator<ValidateUserAgent, String> {

  @Override
  public boolean isValid(final String userAgent, final ConstraintValidatorContext cxt) {
    if (userAgent == null || userAgent.isEmpty()) {
      cxt.disableDefaultConstraintViolation();
      cxt.buildConstraintViolationWithTemplate("user agent header is missing")
          .addConstraintViolation();
      return false;
    } else if (!userAgent.matches("^[a-zA-Z0-9\\-]{1,20}\\/[a-zA-Z0-9\\-\\.]{1,15}$")) {
      cxt.disableDefaultConstraintViolation();
      cxt.buildConstraintViolationWithTemplate(
              "invalid user agent: doesn't match pattern"
                  + " \"^[a-zA-Z0-9\\-]{1,20}\\/[a-zA-Z0-9\\-\\.]{1,15}$\"")
          .addConstraintViolation();
      return false;
    }
    return true;
  }
}
