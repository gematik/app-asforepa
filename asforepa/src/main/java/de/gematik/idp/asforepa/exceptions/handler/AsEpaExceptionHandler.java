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

package de.gematik.idp.asforepa.exceptions.handler;

import de.gematik.idp.asforepa.data.AsEpaErrorCode;
import de.gematik.idp.asforepa.data.AsEpaErrorResponse;
import de.gematik.idp.asforepa.exceptions.AsEpaException;
import jakarta.validation.ConstraintViolationException;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

@ControllerAdvice
@RequiredArgsConstructor
@Slf4j
public class AsEpaExceptionHandler {

  @ExceptionHandler(AsEpaException.class)
  public ResponseEntity<AsEpaErrorResponse> handleAsEpaException(final AsEpaException exc) {
    log.info("AsEpaException: {}", exc.getMessage());
    final AsEpaErrorResponse body = getBody(exc);
    return new ResponseEntity<>(body, getHeader(), exc.getStatusCode());
  }

  @ExceptionHandler(RuntimeException.class)
  public ResponseEntity<AsEpaErrorResponse> handleRuntimeException(final RuntimeException exc) {
    return handleAsEpaException(
        new AsEpaException(
            "AsEpa Runtime Exception: " + exc.getMessage(),
            exc,
            HttpStatus.INTERNAL_SERVER_ERROR,
            AsEpaErrorCode.INTERNAL_ERROR));
  }

  @ExceptionHandler({
    MissingServletRequestParameterException.class,
    ConstraintViolationException.class
  })
  public ResponseEntity<AsEpaErrorResponse> handleValidationException(final Exception exc) {
    return handleAsEpaException(
        new AsEpaException(
            exc.getMessage(), exc, HttpStatus.BAD_REQUEST, AsEpaErrorCode.MALFORMED_REQUEST));
  }

  @ExceptionHandler(MethodArgumentNotValidException.class)
  public ResponseEntity<AsEpaErrorResponse> handleMethodArgumentNotValidException(
      final MethodArgumentNotValidException exc) {
    if (exc.getMessage().contains("missing")) {
      return handleAsEpaException(
          new AsEpaException(
              exc.getMessage(), exc, HttpStatus.BAD_REQUEST, AsEpaErrorCode.MALFORMED_REQUEST));
    }
    return handleAsEpaException(
        new AsEpaException(
            exc.getMessage(), exc, HttpStatus.FORBIDDEN, AsEpaErrorCode.INVALID_AUTH));
  }

  private HttpHeaders getHeader() {
    final HttpHeaders responseHeaders = new HttpHeaders();
    responseHeaders.add(HttpHeaders.CONTENT_TYPE, "application/json; charset=utf-8");
    responseHeaders.remove(HttpHeaders.CACHE_CONTROL);
    responseHeaders.remove(HttpHeaders.PRAGMA);
    return responseHeaders;
  }

  private AsEpaErrorResponse getBody(final AsEpaException exception) {
    return AsEpaErrorResponse.builder()
        .errorDetail(exception.getReason())
        .errorCode(
            Optional.of(exception.getAsforepaErrorCode()).orElse(AsEpaErrorCode.INVALID_AUTH))
        .build();
  }
}
