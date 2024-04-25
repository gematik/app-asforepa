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

package de.gematik.idp.asforepa;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class AsEpaConstants {

  public static final String CODE_CHALLENGE_METHOD = "S256";
  public static final String AUTH_CODE_ENDPOINT = "/epa/authz/v1/send_authcode_sc";
  public static final String NONCE_ENDPOINT = "/epa/authz/v1/getNonce";
  public static final String AUTHZ_REQUEST_SC_ENDPOINT =
      "/epa/authz/v1/send_authorization_request_sc";
  public static final int VAU_NP_STR_LEN = 20;
  public static final int NONCE_STR_LEN = 64;
}
