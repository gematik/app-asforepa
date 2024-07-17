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

package de.gematik.idp.asforepa.exceptions;

import de.gematik.idp.asforepa.data.AsEpaErrorCode;
import java.io.Serial;
import lombok.Getter;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

public class AsEpaException extends ResponseStatusException {

  @Serial private static final long serialVersionUID = -1744157595090697769L;
  @Getter private final AsEpaErrorCode asforepaErrorCode;

  public AsEpaException(final Exception e) {
    super(HttpStatus.INTERNAL_SERVER_ERROR, "Runtime Error", e);
    this.asforepaErrorCode = AsEpaErrorCode.INVALID_AUTH;
  }

  public AsEpaException(final AsEpaErrorCode code, final String message, final HttpStatus status) {
    super(status, message);
    this.asforepaErrorCode = code;
  }

  public AsEpaException(
      final String message,
      final Exception e,
      final HttpStatus status,
      final AsEpaErrorCode asforepaErrorCode) {
    super(status, message, e);
    this.asforepaErrorCode = asforepaErrorCode;
  }
}
