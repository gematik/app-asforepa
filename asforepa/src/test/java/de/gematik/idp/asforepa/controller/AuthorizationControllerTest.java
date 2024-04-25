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

package de.gematik.idp.asforepa.controller;

import static de.gematik.idp.asforepa.AsEpaConstants.AUTHZ_REQUEST_SC_ENDPOINT;
import static de.gematik.idp.asforepa.AsEpaConstants.AUTH_CODE_ENDPOINT;
import static de.gematik.idp.asforepa.AsEpaConstants.NONCE_ENDPOINT;
import static de.gematik.idp.brainPoolExtension.BrainpoolAlgorithmSuiteIdentifiers.BRAINPOOL256_USING_SHA256;
import static org.assertj.core.api.Assertions.assertThat;

import de.gematik.idp.asforepa.data.AuthCodeRequest;
import de.gematik.idp.crypto.model.PkiIdentity;
import de.gematik.idp.field.ClaimName;
import de.gematik.idp.tests.PkiKeyResolver;
import de.gematik.idp.token.JsonWebToken;
import java.time.ZonedDateTime;
import kong.unirest.HttpResponse;
import kong.unirest.JsonNode;
import kong.unirest.Unirest;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpStatus;

@Slf4j
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ExtendWith(PkiKeyResolver.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class AuthorizationControllerTest {

  @LocalServerPort private int localServerPort;
  private String testHostUrl;
  private JsonWebToken clientAttest;

  private final String validAuthCode =
      "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwiY3R5IjoiTkpXVCIsImV4cCI6MTcwMTM0MTkxNX0..YokE-g-EdrYxp6BK.CNldvZZwQuPHfkl3X9dNXVjk2M2LyKj_3A85dtEOGfAG5knjl7Q9P5ce8WoVp8SiXmNm63eUI9XcpFOjdAjxVTrHufnRUYjMZY4VZvXhqDW1Zalz_qC7eVNCiAZE2nXy6ozeLJmibLhgp2flLCGT-Ap1sVH8u6LZflcu-cIPhYR89A2pUh40Kg0ItCtJ1dqG6vinlsMRLs8t2oc5G4-gmI6O-1IlN2ekSTS6zGkq301YueHY8xGyij9SPoIxoiwBuo5C2lDBjWXNMCTKy9JPEl4S3vevg9UFO4bGaw5myoH8xN-S07ZKm3EnkvlzKXdTrBmcFusKE9NOBH4fgLmO4AFHqCEVDmHm7OAejVpRueSKAQZ18VZFUkqPdBYjFkpI_-Q45qBVIVAICsXFSa62LO6uZw6qDeME7c4NonTJCijcQ-RvFGc5Am2A7uJ1jzxiocpU4qRume3V-yWn9_tz0gcBqfUa2ejM2SziXg3PQzYYJ7bxTzWvbuNtBQhA_wzxr8eWf-4Z3NZSsuGzkX3ru5xTDrAJvivm01MqySUZkJz4Ho-kwJ2Fef5sVVMx8EN5fdxvYKUpGtco214a5gdFwVmPg3IiroXR264KWRP9lMgkBLgCyeQXQ07dR4_vl9uU47ytVFzQdshVpK3-1kSq_4SFEzvixCLZqRR4Mv7-PjF8Jmcdftp1jt7zg0Syt7PLYY4hCJCWe_Ftk2G7QD79kPPkvxwKbP1MqxWwliN6uUIYN8UMaIvu-6oPLYeoa8BaAoQiG9tdFL_UXXAGB-tW-VT-1ONofwr6_ZJI7n4jtO5-AZ1ccS1Oocqsc9kDnsFfNouMPTp0HcS690LN1oP-RkRnA3c-dmdSCJdsjsrI2I0tkh5pxlWs_Sg_vn10BjGtYaQHLGdT8cEf8nSRtrZLj1HkAYc5uxuVzJ84enIwQkFEn6dwJRShglxWw9DCWv7sTvww_PNw1Kt8BrzXuPJ7pOP5qi2MJjkOaJ-gqIp4NzGQ7n4Q1vv4ERgTiZlLSm_7fofd_GN4QFp-45DpnHXPtKyAKDbVXTh73myiPbgIIlhG7aaO6PW4aw7z2VuPaVXhv0932UdkdQ7CvJrWDsnLmUIviu72Z7uFA7aI4ilpT4yPcdv2c3Se1cnG4mITOGycBfMtX41tglv5k-YjMdzocWegKgZKwk6hk39O26FxLwto_xfr_2U2_y1S67dRviCRUcCPSmusYUtxKtb_mG-fGyt6hrlWN26y5LKvmB0mUH6kyUSTzyfzLmc4M6ExCs2cO8JpSGENHP5itwMCQ-HxRJ1sfH2LlMn7ECSaz6kPeaKPT2Rrvxck0GF2R-dqY_NMTeC8CV9BJWP9HNpGbxELe7j_RBkPcwXednfHFRBd8r24rZn7gHVi2Dd33g.Xtx_4AO2Gfbz1NeyzfSmaw";

  @SneakyThrows
  @BeforeAll
  void setup(
      @PkiKeyResolver.Filename("833621999741600-2_c.hci.aut-apo-ecc")
          final PkiIdentity smcbIdentityEcc) {
    testHostUrl = "http://localhost:" + localServerPort;
    log.info("testHostUrl: " + testHostUrl);
    Unirest.config().reset();
    Unirest.config().followRedirects(false);
    final JwtClaims claims = new JwtClaims();
    claims.setClaim(
        ClaimName.NONCE.getJoseName(),
        "7721435277f5d0137b17ef8b835ca03cf09dc23926aa1766e4f8132433ff37d6");
    claims.setClaim(ClaimName.ISSUED_AT.getJoseName(), ZonedDateTime.now().toEpochSecond());
    final JsonWebSignature jsonWebSignature = new JsonWebSignature();
    jsonWebSignature.setPayload(claims.toJson());
    jsonWebSignature.setAlgorithmHeaderValue(BRAINPOOL256_USING_SHA256);
    jsonWebSignature.setKey(smcbIdentityEcc.getPrivateKey());

    jsonWebSignature.setHeader("typ", "JWT");
    jsonWebSignature.setCertificateChainHeaderValue(smcbIdentityEcc.getCertificate());
    final String compactSerialization = jsonWebSignature.getCompactSerialization();
    clientAttest = new JsonWebToken(compactSerialization);
  }

  @Test
  void validNonceRequest_response200() {
    assertThat(Unirest.get(testHostUrl + NONCE_ENDPOINT).asJson().getStatus())
        .isEqualTo(HttpStatus.OK.value());
  }

  @Test
  void validNonceRequest_correctJsonBody() {
    final HttpResponse<JsonNode> response = Unirest.get(testHostUrl + NONCE_ENDPOINT).asJson();
    assertThat(response.getBody().getObject().keySet()).containsExactlyInAnyOrder("nonce");
  }

  @Test
  void validAuthzRequest_response302() {
    assertThat(Unirest.get(testHostUrl + AUTHZ_REQUEST_SC_ENDPOINT).asEmpty().getStatus())
        .isEqualTo(HttpStatus.FOUND.value());
  }

  @Test
  void validAuthzRequest_responseHasCorrectLocation() {
    assertThat(
            Unirest.get(testHostUrl + AUTHZ_REQUEST_SC_ENDPOINT)
                .asEmpty()
                .getHeaders()
                .getFirst("location"))
        .contains("redirect_uri=")
        .contains("client_id=")
        .contains("state=")
        .contains("nonce=")
        .contains("code_challenge=")
        .contains("code_challenge_method=S256")
        .contains("response_type=code")
        .contains("scope=epa+openid");
  }

  @Test
  void validSendAuthCodeRequest_response200() {
    final AuthCodeRequest authCodeRequest =
        new AuthCodeRequest(validAuthCode, clientAttest.getRawString());
    assertThat(
            Unirest.post(testHostUrl + AUTH_CODE_ENDPOINT)
                .header("Content-Type", "application/json")
                // .header("User-Agent", "Mozilla/5.0")
                .body(authCodeRequest)
                .asString()
                .getStatus())
        .isEqualTo(HttpStatus.OK.value());
  }

  @Test
  void validSendAuthCodeRequest_response200_checkContentType() {
    final AuthCodeRequest authCodeRequest =
        new AuthCodeRequest(validAuthCode, clientAttest.getRawString());
    assertThat(
            Unirest.post(testHostUrl + AUTH_CODE_ENDPOINT)
                .header("Content-Type", "application/json")
                .body(authCodeRequest)
                .asString()
                .getHeaders()
                .getFirst("content-type"))
        .isEqualTo("application/json");
  }

  @Test
  void validSendAuthCodeRequest_response200_checkVNPisHex() {
    final AuthCodeRequest authCodeRequest =
        new AuthCodeRequest(validAuthCode, clientAttest.getRawString());
    assertThat(
            Unirest.post(testHostUrl + AUTH_CODE_ENDPOINT)
                .header("Content-Type", "application/json")
                .body(authCodeRequest)
                .asString()
                .getBody())
        .isHexadecimal();
  }

  @Test
  void validSendAuthCodeRequestValidUserAgent_response200() {
    final AuthCodeRequest authCodeRequest =
        new AuthCodeRequest(validAuthCode, clientAttest.getRawString());
    assertThat(
            Unirest.post(testHostUrl + AUTH_CODE_ENDPOINT)
                .header("Content-Type", "application/json")
                .header("User-Agent", "CLIENTID1234567890AB/2.1.12-45")
                .body(authCodeRequest)
                .asString()
                .getStatus())
        .isEqualTo(HttpStatus.OK.value());
  }

  @Test
  void invalidSendAuthCodeRequest_emptyAuthCode() {
    final AuthCodeRequest authCodeRequest = new AuthCodeRequest("", clientAttest.getRawString());
    assertThat(
            Unirest.post(testHostUrl + AUTH_CODE_ENDPOINT)
                .header("Content-Type", "application/json")
                .body(authCodeRequest)
                .asString()
                .getStatus())
        .isEqualTo(HttpStatus.BAD_REQUEST.value());
  }

  @Test
  void invalidSendAuthCodeRequest_emptyAuthCode_message() {
    final AuthCodeRequest authCodeRequest = new AuthCodeRequest("", clientAttest.getRawString());
    assertThat(
            Unirest.post(testHostUrl + AUTH_CODE_ENDPOINT)
                .header("Content-Type", "application/json")
                .body(authCodeRequest)
                .asJson()
                .getBody()
                .getObject()
                .getString("error_description"))
        .contains("auth code is invalid");
  }

  @Test
  void invalidSendAuthCodeRequest_wrongHeaderClaimsInAuthCode() {
    final String invalidAuthCode =
        "eyJhbGciOiJkaXIiLCJjdHkiOiJOSldUIiwiZXhwIjoxNzAxMzQxOTE1fQ..YokE-g-EdrYxp6BK.CNldvZZwQuPHfkl3X9dNXVjk2M2LyKj_3A85dtEOGfAG5knjl7Q9P5ce8WoVp8SiXmNm63eUI9XcpFOjdAjxVTrHufnRUYjMZY4VZvXhqDW1Zalz_qC7eVNCiAZE2nXy6ozeLJmibLhgp2flLCGT-Ap1sVH8u6LZflcu-cIPhYR89A2pUh40Kg0ItCtJ1dqG6vinlsMRLs8t2oc5G4-gmI6O-1IlN2ekSTS6zGkq301YueHY8xGyij9SPoIxoiwBuo5C2lDBjWXNMCTKy9JPEl4S3vevg9UFO4bGaw5myoH8xN-S07ZKm3EnkvlzKXdTrBmcFusKE9NOBH4fgLmO4AFHqCEVDmHm7OAejVpRueSKAQZ18VZFUkqPdBYjFkpI_-Q45qBVIVAICsXFSa62LO6uZw6qDeME7c4NonTJCijcQ-RvFGc5Am2A7uJ1jzxiocpU4qRume3V-yWn9_tz0gcBqfUa2ejM2SziXg3PQzYYJ7bxTzWvbuNtBQhA_wzxr8eWf-4Z3NZSsuGzkX3ru5xTDrAJvivm01MqySUZkJz4Ho-kwJ2Fef5sVVMx8EN5fdxvYKUpGtco214a5gdFwVmPg3IiroXR264KWRP9lMgkBLgCyeQXQ07dR4_vl9uU47ytVFzQdshVpK3-1kSq_4SFEzvixCLZqRR4Mv7-PjF8Jmcdftp1jt7zg0Syt7PLYY4hCJCWe_Ftk2G7QD79kPPkvxwKbP1MqxWwliN6uUIYN8UMaIvu-6oPLYeoa8BaAoQiG9tdFL_UXXAGB-tW-VT-1ONofwr6_ZJI7n4jtO5-AZ1ccS1Oocqsc9kDnsFfNouMPTp0HcS690LN1oP-RkRnA3c-dmdSCJdsjsrI2I0tkh5pxlWs_Sg_vn10BjGtYaQHLGdT8cEf8nSRtrZLj1HkAYc5uxuVzJ84enIwQkFEn6dwJRShglxWw9DCWv7sTvww_PNw1Kt8BrzXuPJ7pOP5qi2MJjkOaJ-gqIp4NzGQ7n4Q1vv4ERgTiZlLSm_7fofd_GN4QFp-45DpnHXPtKyAKDbVXTh73myiPbgIIlhG7aaO6PW4aw7z2VuPaVXhv0932UdkdQ7CvJrWDsnLmUIviu72Z7uFA7aI4ilpT4yPcdv2c3Se1cnG4mITOGycBfMtX41tglv5k-YjMdzocWegKgZKwk6hk39O26FxLwto_xfr_2U2_y1S67dRviCRUcCPSmusYUtxKtb_mG-fGyt6hrlWN26y5LKvmB0mUH6kyUSTzyfzLmc4M6ExCs2cO8JpSGENHP5itwMCQ-HxRJ1sfH2LlMn7ECSaz6kPeaKPT2Rrvxck0GF2R-dqY_NMTeC8CV9BJWP9HNpGbxELe7j_RBkPcwXednfHFRBd8r24rZn7gHVi2Dd33g.Xtx_4AO2Gfbz1NeyzfSmaw";
    final AuthCodeRequest authCodeRequest =
        new AuthCodeRequest(invalidAuthCode, clientAttest.getRawString());
    assertThat(
            Unirest.post(testHostUrl + AUTH_CODE_ENDPOINT)
                .header("Content-Type", "application/json")
                .body(authCodeRequest)
                .asString()
                .getStatus())
        .isEqualTo(HttpStatus.BAD_REQUEST.value());
  }

  @Test
  void invalidSendAuthCodeRequest_wrongHeaderClaimsInAuthCode_message() {
    final String invalidAuthCode =
        "eyJhbGciOiJkaXIiLCJjdHkiOiJOSldUIiwiZXhwIjoxNzAxMzQxOTE1fQ..YokE-g-EdrYxp6BK.CNldvZZwQuPHfkl3X9dNXVjk2M2LyKj_3A85dtEOGfAG5knjl7Q9P5ce8WoVp8SiXmNm63eUI9XcpFOjdAjxVTrHufnRUYjMZY4VZvXhqDW1Zalz_qC7eVNCiAZE2nXy6ozeLJmibLhgp2flLCGT-Ap1sVH8u6LZflcu-cIPhYR89A2pUh40Kg0ItCtJ1dqG6vinlsMRLs8t2oc5G4-gmI6O-1IlN2ekSTS6zGkq301YueHY8xGyij9SPoIxoiwBuo5C2lDBjWXNMCTKy9JPEl4S3vevg9UFO4bGaw5myoH8xN-S07ZKm3EnkvlzKXdTrBmcFusKE9NOBH4fgLmO4AFHqCEVDmHm7OAejVpRueSKAQZ18VZFUkqPdBYjFkpI_-Q45qBVIVAICsXFSa62LO6uZw6qDeME7c4NonTJCijcQ-RvFGc5Am2A7uJ1jzxiocpU4qRume3V-yWn9_tz0gcBqfUa2ejM2SziXg3PQzYYJ7bxTzWvbuNtBQhA_wzxr8eWf-4Z3NZSsuGzkX3ru5xTDrAJvivm01MqySUZkJz4Ho-kwJ2Fef5sVVMx8EN5fdxvYKUpGtco214a5gdFwVmPg3IiroXR264KWRP9lMgkBLgCyeQXQ07dR4_vl9uU47ytVFzQdshVpK3-1kSq_4SFEzvixCLZqRR4Mv7-PjF8Jmcdftp1jt7zg0Syt7PLYY4hCJCWe_Ftk2G7QD79kPPkvxwKbP1MqxWwliN6uUIYN8UMaIvu-6oPLYeoa8BaAoQiG9tdFL_UXXAGB-tW-VT-1ONofwr6_ZJI7n4jtO5-AZ1ccS1Oocqsc9kDnsFfNouMPTp0HcS690LN1oP-RkRnA3c-dmdSCJdsjsrI2I0tkh5pxlWs_Sg_vn10BjGtYaQHLGdT8cEf8nSRtrZLj1HkAYc5uxuVzJ84enIwQkFEn6dwJRShglxWw9DCWv7sTvww_PNw1Kt8BrzXuPJ7pOP5qi2MJjkOaJ-gqIp4NzGQ7n4Q1vv4ERgTiZlLSm_7fofd_GN4QFp-45DpnHXPtKyAKDbVXTh73myiPbgIIlhG7aaO6PW4aw7z2VuPaVXhv0932UdkdQ7CvJrWDsnLmUIviu72Z7uFA7aI4ilpT4yPcdv2c3Se1cnG4mITOGycBfMtX41tglv5k-YjMdzocWegKgZKwk6hk39O26FxLwto_xfr_2U2_y1S67dRviCRUcCPSmusYUtxKtb_mG-fGyt6hrlWN26y5LKvmB0mUH6kyUSTzyfzLmc4M6ExCs2cO8JpSGENHP5itwMCQ-HxRJ1sfH2LlMn7ECSaz6kPeaKPT2Rrvxck0GF2R-dqY_NMTeC8CV9BJWP9HNpGbxELe7j_RBkPcwXednfHFRBd8r24rZn7gHVi2Dd33g.Xtx_4AO2Gfbz1NeyzfSmaw";
    final AuthCodeRequest authCodeRequest =
        new AuthCodeRequest(invalidAuthCode, clientAttest.getRawString());
    assertThat(
            Unirest.post(testHostUrl + AUTH_CODE_ENDPOINT)
                .header("Content-Type", "application/json")
                .body(authCodeRequest)
                .asJson()
                .getBody()
                .getObject()
                .getString("error_description"))
        .contains("auth code is invalid");
  }

  @Test
  void invalidSendAuthCodeRequest_invalidClientAttest() {
    final AuthCodeRequest authCodeRequest = new AuthCodeRequest(validAuthCode, "noJwtClientAttest");
    assertThat(
            Unirest.post(testHostUrl + AUTH_CODE_ENDPOINT)
                .header("Content-Type", "application/json")
                .body(authCodeRequest)
                .asString()
                .getStatus())
        .isEqualTo(HttpStatus.BAD_REQUEST.value());
  }

  @Test
  void invalidSendAuthCodeRequest_invalidClientAttest_message() {
    final AuthCodeRequest authCodeRequest = new AuthCodeRequest(validAuthCode, "noJwtClientAttest");
    assertThat(
            Unirest.post(testHostUrl + AUTH_CODE_ENDPOINT)
                .header("Content-Type", "application/json")
                .body(authCodeRequest)
                .asJson()
                .getBody()
                .getObject()
                .getString("error_description"))
        .contains("client attest is invalid");
  }

  @Test
  void invalidSendAuthCodeRequest_invalidSignatureClientAttest() {
    final String clientAttestInvalidSig =
        "eyJhbGciOiJCUDI1NlIxIiwidHlwIjoiSldUIiwieDVjIjpbIk1JSUVCakNDQTZ5Z0F3SUJBZ0lIQVN1b0FGWjArekFLQmdncWhrak9QUVFEQWpDQm1qRUxNQWtHQTFVRUJoTUNSRVV4SHpBZEJnTlZCQW9NRm1kbGJXRjBhV3NnUjIxaVNDQk9UMVF0VmtGTVNVUXhTREJHQmdOVkJBc01QMGx1YzNScGRIVjBhVzl1SUdSbGN5QkhaWE4xYm1Sb1pXbDBjM2RsYzJWdWN5MURRU0JrWlhJZ1ZHVnNaVzFoZEdscmFXNW1jbUZ6ZEhKMWEzUjFjakVnTUI0R0ExVUVBd3dYUjBWTkxsTk5RMEl0UTBFMU1TQlVSVk5VTFU5T1RGa3dIaGNOTWpRd01qSTNNREF3TURBd1doY05Namt3TWpJM01qTTFPVFU1V2pDQnhURUxNQWtHQTFVRUJoTUNSRVV4SERBYUJnTlZCQWdNRTA1dmNtUnlhR1ZwYmkxWFpYTjBabUZzWlc0eEVqQVFCZ05WQkFjTUNVSnBaV3hsWm1Wc1pERU9NQXdHQTFVRUVRd0ZNek0yTURJeEh6QWRCZ05WQkFrTUZrSmhZMnR3ZFd4MlpYSmZVM1J5WVhOelpWODNOemN4S2pBb0JnTlZCQW9NSVRNdE1pMUZVRUV0T0RNek5qSXhPVGs1TnpReE5qQXdJRTVQVkMxV1FVeEpSREVuTUNVR0ExVUVBd3dlUVhOamFHOW1abk5qYUdVZ1FYQnZkR2hsYTJVZ1ZFVlRWQzFQVGt4Wk1Gb3dGQVlIS29aSXpqMENBUVlKS3lRREF3SUlBUUVIQTBJQUJLVGpWOUY4RFJLNmhraTU5MWxNNVNic0gvUnE3eDhLT1FoanBvWWFJc3NqaDdwRFh4OXFldndNUEdWdS92Q1RCcnl3dU91SFNKVDR4M212RnZUK0grR2pnZ0d0TUlJQnFUQjJCZ1VySkFnREF3UnRNR3VrS0RBbU1Rc3dDUVlEVlFRR0V3SkVSVEVYTUJVR0ExVUVDZ3dPUVVzZ1FuSmhibVJsYm1KMWNtY3dQekE5TURzd09UQVhEQlhEbG1abVpXNTBiR2xqYUdVZ1FYQnZkR2hsYTJVd0NRWUhLb0lVQUV3RU5oTVRNeTB5TGpNek16TTVPQzVVWlhOMFQyNXNlVEE3QmdnckJnRUZCUWNCQVFRdk1DMHdLd1lJS3dZQkJRVUhNQUdHSDJoMGRIQTZMeTlsYUdOaExtZGxiV0YwYVdzdVpHVXZaV05qTFc5amMzQXdJUVlEVlIwUkJCb3dHS0FXQmdOVkJBT2dEd3dOVDJWMGEyVnlMVWR5ZFhCd1pUQWRCZ05WSFE0RUZnUVVodFljdlJVS2Z6UXU0SjVyeFI2M2gwYXhuSHd3RXdZRFZSMGxCQXd3Q2dZSUt3WUJCUVVIQXdJd1hBWURWUjBnQkZVd1V6QTdCZ2dxZ2hRQVRBU0JJekF2TUMwR0NDc0dBUVVGQndJQkZpRm9kSFJ3T2k4dmQzZDNMbWRsYldGMGFXc3VaR1V2WjI4dmNHOXNhV05wWlhNd0NRWUhLb0lVQUV3RVRUQUpCZ2NxZ2hRQVRBUmxNQjhHQTFVZEl3UVlNQmFBRkFhWTZRSlYvOG1mWEtObER2RmQ0aUQxaFB1VE1BNEdBMVVkRHdFQi93UUVBd0lIZ0RBTUJnTlZIUk1CQWY4RUFqQUFNQW9HQ0NxR1NNNDlCQU1DQTBnQU1FVUNJRTI0bFMxdkxuQVVLZFYyLyt2YmM1VFBhazNOU2V2MVRkbXhMRTFFZEJtcUFpRUFoek83R1ArSkE2NTQzdmdEeXJzcXlxendCV2ZGM0pHUWdqcFJOYmRFSkZRPSJdfQ.eyJub25jZSI6Ijc3MjE0MzdmNWQwMTM3YjE3ZWY4YjgzNWNhMDNjZjA5ZGMyMzkyNmFhMTc2NmU0ZjgxMzI0MzNmZjM3ZDYiLCJpYXQiOjE3MTA4NTQ5NTh9.bmAolht7OIH7K1rvdkXP_t6wJdXrC4JgR8uuNvNXXKSYxY3myIPEmVB6Dmyk7SLyhI0Z5OhQFzzUd36GXVllpg";
    final AuthCodeRequest authCodeRequest =
        new AuthCodeRequest(validAuthCode, clientAttestInvalidSig);
    assertThat(
            Unirest.post(testHostUrl + AUTH_CODE_ENDPOINT)
                .header("Content-Type", "application/json")
                .body(authCodeRequest)
                .asString()
                .getStatus())
        .isEqualTo(HttpStatus.BAD_REQUEST.value());
  }

  @Test
  void invalidSendAuthCodeRequest_invalidSignatureClientAttest_message() {
    final String clientAttestInvalidSig =
        "eyJhbGciOiJCUDI1NlIxIiwidHlwIjoiSldUIiwieDVjIjpbIk1JSUVCakNDQTZ5Z0F3SUJBZ0lIQVN1b0FGWjArekFLQmdncWhrak9QUVFEQWpDQm1qRUxNQWtHQTFVRUJoTUNSRVV4SHpBZEJnTlZCQW9NRm1kbGJXRjBhV3NnUjIxaVNDQk9UMVF0VmtGTVNVUXhTREJHQmdOVkJBc01QMGx1YzNScGRIVjBhVzl1SUdSbGN5QkhaWE4xYm1Sb1pXbDBjM2RsYzJWdWN5MURRU0JrWlhJZ1ZHVnNaVzFoZEdscmFXNW1jbUZ6ZEhKMWEzUjFjakVnTUI0R0ExVUVBd3dYUjBWTkxsTk5RMEl0UTBFMU1TQlVSVk5VTFU5T1RGa3dIaGNOTWpRd01qSTNNREF3TURBd1doY05Namt3TWpJM01qTTFPVFU1V2pDQnhURUxNQWtHQTFVRUJoTUNSRVV4SERBYUJnTlZCQWdNRTA1dmNtUnlhR1ZwYmkxWFpYTjBabUZzWlc0eEVqQVFCZ05WQkFjTUNVSnBaV3hsWm1Wc1pERU9NQXdHQTFVRUVRd0ZNek0yTURJeEh6QWRCZ05WQkFrTUZrSmhZMnR3ZFd4MlpYSmZVM1J5WVhOelpWODNOemN4S2pBb0JnTlZCQW9NSVRNdE1pMUZVRUV0T0RNek5qSXhPVGs1TnpReE5qQXdJRTVQVkMxV1FVeEpSREVuTUNVR0ExVUVBd3dlUVhOamFHOW1abk5qYUdVZ1FYQnZkR2hsYTJVZ1ZFVlRWQzFQVGt4Wk1Gb3dGQVlIS29aSXpqMENBUVlKS3lRREF3SUlBUUVIQTBJQUJLVGpWOUY4RFJLNmhraTU5MWxNNVNic0gvUnE3eDhLT1FoanBvWWFJc3NqaDdwRFh4OXFldndNUEdWdS92Q1RCcnl3dU91SFNKVDR4M212RnZUK0grR2pnZ0d0TUlJQnFUQjJCZ1VySkFnREF3UnRNR3VrS0RBbU1Rc3dDUVlEVlFRR0V3SkVSVEVYTUJVR0ExVUVDZ3dPUVVzZ1FuSmhibVJsYm1KMWNtY3dQekE5TURzd09UQVhEQlhEbG1abVpXNTBiR2xqYUdVZ1FYQnZkR2hsYTJVd0NRWUhLb0lVQUV3RU5oTVRNeTB5TGpNek16TTVPQzVVWlhOMFQyNXNlVEE3QmdnckJnRUZCUWNCQVFRdk1DMHdLd1lJS3dZQkJRVUhNQUdHSDJoMGRIQTZMeTlsYUdOaExtZGxiV0YwYVdzdVpHVXZaV05qTFc5amMzQXdJUVlEVlIwUkJCb3dHS0FXQmdOVkJBT2dEd3dOVDJWMGEyVnlMVWR5ZFhCd1pUQWRCZ05WSFE0RUZnUVVodFljdlJVS2Z6UXU0SjVyeFI2M2gwYXhuSHd3RXdZRFZSMGxCQXd3Q2dZSUt3WUJCUVVIQXdJd1hBWURWUjBnQkZVd1V6QTdCZ2dxZ2hRQVRBU0JJekF2TUMwR0NDc0dBUVVGQndJQkZpRm9kSFJ3T2k4dmQzZDNMbWRsYldGMGFXc3VaR1V2WjI4dmNHOXNhV05wWlhNd0NRWUhLb0lVQUV3RVRUQUpCZ2NxZ2hRQVRBUmxNQjhHQTFVZEl3UVlNQmFBRkFhWTZRSlYvOG1mWEtObER2RmQ0aUQxaFB1VE1BNEdBMVVkRHdFQi93UUVBd0lIZ0RBTUJnTlZIUk1CQWY4RUFqQUFNQW9HQ0NxR1NNNDlCQU1DQTBnQU1FVUNJRTI0bFMxdkxuQVVLZFYyLyt2YmM1VFBhazNOU2V2MVRkbXhMRTFFZEJtcUFpRUFoek83R1ArSkE2NTQzdmdEeXJzcXlxendCV2ZGM0pHUWdqcFJOYmRFSkZRPSJdfQ.eyJub25jZSI6Ijc3MjE0MzdmNWQwMTM3YjE3ZWY4YjgzNWNhMDNjZjA5ZGMyMzkyNmFhMTc2NmU0ZjgxMzI0MzNmZjM3ZDYiLCJpYXQiOjE3MTA4NTQ5NTh9.bmAolht7OIH7K1rvdkXP_t6wJdXrC4JgR8uuNvNXXKSYxY3myIPEmVB6Dmyk7SLyhI0Z5OhQFzzUd36GXVllpg";
    final AuthCodeRequest authCodeRequest =
        new AuthCodeRequest(validAuthCode, clientAttestInvalidSig);
    assertThat(
            Unirest.post(testHostUrl + AUTH_CODE_ENDPOINT)
                .header("Content-Type", "application/json")
                .body(authCodeRequest)
                .asJson()
                .getBody()
                .getObject()
                .getString("error_description"))
        .contains("client attest is invalid");
  }
}
