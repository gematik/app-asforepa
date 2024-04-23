#
# Copyright 2024 gematik GmbH
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

@Authz
Feature: Test Authorization Endpoint

  Background:
    When TGR disable HttpClient followRedirects configuration

  @TCID:EPA_AS_AUTHZ_001
  @Approval
  Scenario: Authz Request Endpoint - Gutfall - Validiere Response

  ```
  Wir senden einen Authorization Request an den Authz Server der ePA.
  Die HTTP Response muss:

  - den Code 302 enthalten

    Given TGR clear recorded messages
    When TGR send empty GET request to "http://asforepa/epa/authz/v1/send_authorization_request_sc"
    And TGR find request to path ".*"
    Then TGR current response with attribute "$.responseCode" matches "302"


  @TCID:EPA_AS_AUTHZ_002
  @Approval
  Scenario: Authz Request Endpoint - Gutfall - Validiere Location

  ```
  Wir senden einen Authorization Request an den Authz Server der ePA.
  Die HTTP Response muss:

  - die korrekten Parameter in der Location enthalten

    Given TGR clear recorded messages
    When TGR send empty GET request to "http://asforepa/epa/authz/v1/send_authorization_request_sc"
    And TGR find request to path ".*"
    Then TGR current response with attribute "$.header.Location" matches ".*redirect_uri=.*"
    Then TGR current response with attribute "$.header.Location" matches ".*client_id=.*"
    Then TGR current response with attribute "$.header.Location" matches ".*state=.*"
    Then TGR current response with attribute "$.header.Location" matches ".*nonce=.*"
    Then TGR current response with attribute "$.header.Location" matches ".*code_challenge=.*"
    Then TGR current response with attribute "$.header.Location" matches ".*code_challenge_method=S256.*"
    Then TGR current response with attribute "$.header.Location" matches ".*response_type=code.*"
