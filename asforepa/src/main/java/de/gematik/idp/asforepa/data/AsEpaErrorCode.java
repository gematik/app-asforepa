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

package de.gematik.idp.asforepa.data;

import com.fasterxml.jackson.annotation.JsonValue;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;

@JsonNaming(PropertyNamingStrategies.LowerCamelCaseStrategy.class)
public enum AsEpaErrorCode {
  MALFORMED_REQUEST("malformedRequest"),
  INVALID_AUTH("invalAuth"),
  NO_RESOURCE("noResource"),
  STATUS_MISMATCH("statusMismatch"),
  INTERNAL_ERROR("internalError");

  private final String serializationValue;

  @JsonValue
  public String getSerializationValue() {
    return this.serializationValue;
  }

  private AsEpaErrorCode(final String serializationValue) {
    this.serializationValue = serializationValue;
  }
}
