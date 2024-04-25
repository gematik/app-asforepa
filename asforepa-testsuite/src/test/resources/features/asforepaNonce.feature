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
Feature: Test Nonce Endpoint


  @TCID:EPA_AS_NONCE_001
  @Approval
  Scenario: Nonce Request Endpoint - Gutfall - Validiere Response

  ```
  Wir senden einen getNonce Request an den Authz Server der ePA.
  Die HTTP Response muss:

  - den Code 200 enthalten

    Given TGR clear recorded messages
    When TGR send empty GET request to "http://asforepa/epa/authz/v1/getNonce"
    And TGR find request to path ".*"
    Then TGR current response with attribute "$.responseCode" matches "200"


  @TCID:EPA_AS_NONCE_002
  @Approval
  Scenario: Nonce Request Endpoint - Gutfall - Validiere Body

  ```
  Wir senden einen getNonce Request an den Authz Server der ePA.
  Die HTTP Response muss:

  - den korrekten Json Body enthalten

    Given TGR clear recorded messages
    When TGR send empty GET request to "http://asforepa/epa/authz/v1/getNonce"
    And TGR find request to path ".*"
    Then TGR current response at "$.body" matches as JSON:
        """
          {
            nonce:                           '.*',
          }
        """
    