#
# Copyright (Change Date see Readme), gematik GmbH
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
# *******
#
# For additional notes and disclaimer from gematik and in case of changes by gematik find details in the "Readme" file.
#

@Authz
Feature: Test Send Auth Code Endpoint

  Background:
    When TGR disable HttpClient followRedirects configuration

  @TCID:EPA_AS_AUTHCODE_001
  @Approval
  Scenario: Send Auth Code Request Endpoint - Gutfall - Validiere Response

  ```
  Wir senden einen Auth Code an den Authz Server der ePA.
  Die HTTP Response muss:

  - den Code 200 enthalten

    Given TGR clear recorded messages
    When TGR set default header 'x-useragent' to '${asforepa.validUserAgent}'
    When TGR send empty GET request to "http://asforepa/epa/authz/v1/getNonce"
    And TGR find first request to path ".*"
    And generate client attest from nonce "!{rbel:currentResponseAsString('$.body.nonce')}" and save as clientAttest
    Then TGR current response with attribute "$.responseCode" matches "200"
    Given TGR clear recorded messages
    When TGR set default header 'Content-Type' to 'application/json'
    When TGR set default header 'x-useragent' to '${asforepa.validUserAgent}'
    And TGR send POST request to "http://asforepa/epa/authz/v1/send_authcode_sc" with multiline body:
    """
          {
               "authorizationCode": "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwiY3R5IjoiTkpXVCIsImV4cCI6MTcwMTM0MTkxNX0..YokE-g-EdrYxp6BK.CNldvZZwQuPHfkl3X9dNXVjk2M2LyKj_3A85dtEOGfAG5knjl7Q9P5ce8WoVp8SiXmNm63eUI9XcpFOjdAjxVTrHufnRUYjMZY4VZvXhqDW1Zalz_qC7eVNCiAZE2nXy6ozeLJmibLhgp2flLCGT-Ap1sVH8u6LZflcu-cIPhYR89A2pUh40Kg0ItCtJ1dqG6vinlsMRLs8t2oc5G4-gmI6O-1IlN2ekSTS6zGkq301YueHY8xGyij9SPoIxoiwBuo5C2lDBjWXNMCTKy9JPEl4S3vevg9UFO4bGaw5myoH8xN-S07ZKm3EnkvlzKXdTrBmcFusKE9NOBH4fgLmO4AFHqCEVDmHm7OAejVpRueSKAQZ18VZFUkqPdBYjFkpI_-Q45qBVIVAICsXFSa62LO6uZw6qDeME7c4NonTJCijcQ-RvFGc5Am2A7uJ1jzxiocpU4qRume3V-yWn9_tz0gcBqfUa2ejM2SziXg3PQzYYJ7bxTzWvbuNtBQhA_wzxr8eWf-4Z3NZSsuGzkX3ru5xTDrAJvivm01MqySUZkJz4Ho-kwJ2Fef5sVVMx8EN5fdxvYKUpGtco214a5gdFwVmPg3IiroXR264KWRP9lMgkBLgCyeQXQ07dR4_vl9uU47ytVFzQdshVpK3-1kSq_4SFEzvixCLZqRR4Mv7-PjF8Jmcdftp1jt7zg0Syt7PLYY4hCJCWe_Ftk2G7QD79kPPkvxwKbP1MqxWwliN6uUIYN8UMaIvu-6oPLYeoa8BaAoQiG9tdFL_UXXAGB-tW-VT-1ONofwr6_ZJI7n4jtO5-AZ1ccS1Oocqsc9kDnsFfNouMPTp0HcS690LN1oP-RkRnA3c-dmdSCJdsjsrI2I0tkh5pxlWs_Sg_vn10BjGtYaQHLGdT8cEf8nSRtrZLj1HkAYc5uxuVzJ84enIwQkFEn6dwJRShglxWw9DCWv7sTvww_PNw1Kt8BrzXuPJ7pOP5qi2MJjkOaJ-gqIp4NzGQ7n4Q1vv4ERgTiZlLSm_7fofd_GN4QFp-45DpnHXPtKyAKDbVXTh73myiPbgIIlhG7aaO6PW4aw7z2VuPaVXhv0932UdkdQ7CvJrWDsnLmUIviu72Z7uFA7aI4ilpT4yPcdv2c3Se1cnG4mITOGycBfMtX41tglv5k-YjMdzocWegKgZKwk6hk39O26FxLwto_xfr_2U2_y1S67dRviCRUcCPSmusYUtxKtb_mG-fGyt6hrlWN26y5LKvmB0mUH6kyUSTzyfzLmc4M6ExCs2cO8JpSGENHP5itwMCQ-HxRJ1sfH2LlMn7ECSaz6kPeaKPT2Rrvxck0GF2R-dqY_NMTeC8CV9BJWP9HNpGbxELe7j_RBkPcwXednfHFRBd8r24rZn7gHVi2Dd33g.Xtx_4AO2Gfbz1NeyzfSmaw",
               "clientAttest": "${clientAttest}"
          }
        """
    And TGR find first request to path ".*"
    Then TGR current response with attribute "$.responseCode" matches "200"
