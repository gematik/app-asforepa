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

import static org.assertj.core.api.Assertions.assertThat;

import de.gematik.idp.asforepa.data.UserAgentHeader;
import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class UserAgentValidatorTest {
  private Validator validator;

  @BeforeEach
  void setUp() {
    validator = Validation.buildDefaultValidatorFactory().getValidator();
  }

  @Test
  public void validateUserAgent_validUserAgent_maxLength() {
    final UserAgentHeader userAgent = new UserAgentHeader("MyID-123456789876543/1.2.a.b-c.d.3.4");
    final Set<ConstraintViolation<UserAgentHeader>> violations = validator.validate(userAgent);
    assertThat(violations.size()).isEqualTo(0);
  }

  @Test
  public void validateUserAgent_validUserAgent_minLength() {
    final UserAgentHeader userAgent = new UserAgentHeader("-/1");
    final Set<ConstraintViolation<UserAgentHeader>> violations = validator.validate(userAgent);
    assertThat(violations.size()).isEqualTo(0);
  }

  @Test
  public void validateUserAgent_invalidUserAgent_invalidCharInFirstPart() {
    final UserAgentHeader userAgent = new UserAgentHeader("MyID123.4/1.2-3");
    final Set<ConstraintViolation<UserAgentHeader>> violations = validator.validate(userAgent);
    assertThat(violations.size()).isEqualTo(1);
  }

  @Test
  public void validateUserAgent_invalidUserAgent_invalidCharInSecondPart() {
    final UserAgentHeader userAgent = new UserAgentHeader("MyID1234/1.2-3&");
    final Set<ConstraintViolation<UserAgentHeader>> violations = validator.validate(userAgent);
    assertThat(violations.size()).isEqualTo(1);
  }
}
