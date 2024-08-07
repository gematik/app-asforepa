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
import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

class Base64UrlValidatorTest {

  @Test
  void isBase64URL_invalidBase64_1() {
    assertThat(Base64UrlValidator.isBase64URL("U29tZS1iYXNlNjR1cmxlbmNvZGVkLXN0cmluZw=="))
        .isFalse();
  }

  @Test
  void isBase64URL_invalidBase64_2() {
    assertThat(Base64UrlValidator.isBase64URL("U29tZS1iYXNlNjR1cmxlbmNvZGVkLXN0cmluZw/="))
        .isFalse();
  }

  @Test
  void isBase64URL_invalidBase64_3() {
    assertThat(Base64UrlValidator.isBase64URL("U29tZS1iYXNlNjR1cmxlbmNvZGVkLXN0cmluZw+="))
        .isFalse();
  }

  @Test
  void isBase64URL_validBase64() {
    assertThat(Base64UrlValidator.isBase64URL("U29tZS1iYXNlNjR1cmxlbmNvZGVkLXN0cmluZw")).isTrue();
  }

  @Test
  void isBase64URL_authCode_invalidBase64AuthCode() {
    assertThat(
            Base64UrlValidator.isBase64URL(
                "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwiY3R5IjoiTkpXVCIsImV4cCI6MTcwMTM0MTkxNX0..YokE+g+EdrYxp6BK.CNldvZZwQuPHfkl3X9dNXVjk2M2LyKj/3A85dtEOGfAG5knjl7Q9P5ce8WoVp8SiXmNm63eUI9XcpFOjdAjxVTrHufnRUYjMZY4VZvXhqDW1Zalz/qC7eVNCiAZE2nXy6ozeLJmibLhgp2flLCGT+Ap1sVH8u6LZflcu+cIPhYR89A2pUh40Kg0ItCtJ1dqG6vinlsMRLs8t2oc5G4+gmI6O+1IlN2ekSTS6zGkq301YueHY8xGyij9SPoIxoiwBuo5C2lDBjWXNMCTKy9JPEl4S3vevg9UFO4bGaw5myoH8xN+S07ZKm3EnkvlzKXdTrBmcFusKE9NOBH4fgLmO4AFHqCEVDmHm7OAejVpRueSKAQZ18VZFUkqPdBYjFkpI/+Q45qBVIVAICsXFSa62LO6uZw6qDeME7c4NonTJCijcQ+RvFGc5Am2A7uJ1jzxiocpU4qRume3V+yWn9/tz0gcBqfUa2ejM2SziXg3PQzYYJ7bxTzWvbuNtBQhA/wzxr8eWf+4Z3NZSsuGzkX3ru5xTDrAJvivm01MqySUZkJz4Ho+kwJ2Fef5sVVMx8EN5fdxvYKUpGtco214a5gdFwVmPg3IiroXR264KWRP9lMgkBLgCyeQXQ07dR4/vl9uU47ytVFzQdshVpK3+1kSq/4SFEzvixCLZqRR4Mv7+PjF8Jmcdftp1jt7zg0Syt7PLYY4hCJCWe/Ftk2G7QD79kPPkvxwKbP1MqxWwliN6uUIYN8UMaIvu+6oPLYeoa8BaAoQiG9tdFL/UXXAGB+tW+VT+1ONofwr6/ZJI7n4jtO5+AZ1ccS1Oocqsc9kDnsFfNouMPTp0HcS690LN1oP+RkRnA3c+dmdSCJdsjsrI2I0tkh5pxlWs/Sg/vn10BjGtYaQHLGdT8cEf8nSRtrZLj1HkAYc5uxuVzJ84enIwQkFEn6dwJRShglxWw9DCWv7sTvww/PNw1Kt8BrzXuPJ7pOP5qi2MJjkOaJ+gqIp4NzGQ7n4Q1vv4ERgTiZlLSm/7fofd/GN4QFp+45DpnHXPtKyAKDbVXTh73myiPbgIIlhG7aaO6PW4aw7z2VuPaVXhv0932UdkdQ7CvJrWDsnLmUIviu72Z7uFA7aI4ilpT4yPcdv2c3Se1cnG4mITOGycBfMtX41tglv5k+YjMdzocWegKgZKwk6hk39O26FxLwto/xfr/2U2/y1S67dRviCRUcCPSmusYUtxKtb/mG+fGyt6hrlWN26y5LKvmB0mUH6kyUSTzyfzLmc4M6ExCs2cO8JpSGENHP5itwMCQ+HxRJ1sfH2LlMn7ECSaz6kPeaKPT2Rrvxck0GF2R+dqY/NMTeC8CV9BJWP9HNpGbxELe7j/RBkPcwXednfHFRBd8r24rZn7gHVi2Dd33g.Xtx/4AO2Gfbz1NeyzfSmaw"))
        .isFalse();
  }

  @Test
  void isBase64URL_authCode_validBase64UrlAuthCode() {
    assertThat(
            Base64UrlValidator.isBase64URL(
                "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwiY3R5IjoiTkpXVCIsImV4cCI6MTcwMTM0MTkxNX0..YokE-g-EdrYxp6BK.CNldvZZwQuPHfkl3X9dNXVjk2M2LyKj_3A85dtEOGfAG5knjl7Q9P5ce8WoVp8SiXmNm63eUI9XcpFOjdAjxVTrHufnRUYjMZY4VZvXhqDW1Zalz_qC7eVNCiAZE2nXy6ozeLJmibLhgp2flLCGT-Ap1sVH8u6LZflcu-cIPhYR89A2pUh40Kg0ItCtJ1dqG6vinlsMRLs8t2oc5G4-gmI6O-1IlN2ekSTS6zGkq301YueHY8xGyij9SPoIxoiwBuo5C2lDBjWXNMCTKy9JPEl4S3vevg9UFO4bGaw5myoH8xN-S07ZKm3EnkvlzKXdTrBmcFusKE9NOBH4fgLmO4AFHqCEVDmHm7OAejVpRueSKAQZ18VZFUkqPdBYjFkpI_-Q45qBVIVAICsXFSa62LO6uZw6qDeME7c4NonTJCijcQ-RvFGc5Am2A7uJ1jzxiocpU4qRume3V-yWn9_tz0gcBqfUa2ejM2SziXg3PQzYYJ7bxTzWvbuNtBQhA_wzxr8eWf-4Z3NZSsuGzkX3ru5xTDrAJvivm01MqySUZkJz4Ho-kwJ2Fef5sVVMx8EN5fdxvYKUpGtco214a5gdFwVmPg3IiroXR264KWRP9lMgkBLgCyeQXQ07dR4_vl9uU47ytVFzQdshVpK3-1kSq_4SFEzvixCLZqRR4Mv7-PjF8Jmcdftp1jt7zg0Syt7PLYY4hCJCWe_Ftk2G7QD79kPPkvxwKbP1MqxWwliN6uUIYN8UMaIvu-6oPLYeoa8BaAoQiG9tdFL_UXXAGB-tW-VT-1ONofwr6_ZJI7n4jtO5-AZ1ccS1Oocqsc9kDnsFfNouMPTp0HcS690LN1oP-RkRnA3c-dmdSCJdsjsrI2I0tkh5pxlWs_Sg_vn10BjGtYaQHLGdT8cEf8nSRtrZLj1HkAYc5uxuVzJ84enIwQkFEn6dwJRShglxWw9DCWv7sTvww_PNw1Kt8BrzXuPJ7pOP5qi2MJjkOaJ-gqIp4NzGQ7n4Q1vv4ERgTiZlLSm_7fofd_GN4QFp-45DpnHXPtKyAKDbVXTh73myiPbgIIlhG7aaO6PW4aw7z2VuPaVXhv0932UdkdQ7CvJrWDsnLmUIviu72Z7uFA7aI4ilpT4yPcdv2c3Se1cnG4mITOGycBfMtX41tglv5k-YjMdzocWegKgZKwk6hk39O26FxLwto_xfr_2U2_y1S67dRviCRUcCPSmusYUtxKtb_mG-fGyt6hrlWN26y5LKvmB0mUH6kyUSTzyfzLmc4M6ExCs2cO8JpSGENHP5itwMCQ-HxRJ1sfH2LlMn7ECSaz6kPeaKPT2Rrvxck0GF2R-dqY_NMTeC8CV9BJWP9HNpGbxELe7j_RBkPcwXednfHFRBd8r24rZn7gHVi2Dd33g.Xtx_4AO2Gfbz1NeyzfSmaw"))
        .isTrue();
  }

  @Test
  void isBase64URL_clientAttest_validBase64Url() {
    assertThat(
            Base64UrlValidator.isBase64URL(
                "eyJ0eXAiOiJKV1QiLCJ4NWMiOlsiTUlJRUJqQ0NBNnlnQXdJQkFnSUhBU3VvQUZaMCt6QUtCZ2dxaGtqT1BRUURBakNCbWpFTE1Ba0dBMVVFQmhNQ1JFVXhIekFkQmdOVkJBb01GbWRsYldGMGFXc2dSMjFpU0NCT1QxUXRWa0ZNU1VReFNEQkdCZ05WQkFzTVAwbHVjM1JwZEhWMGFXOXVJR1JsY3lCSFpYTjFibVJvWldsMGMzZGxjMlZ1Y3kxRFFTQmtaWElnVkdWc1pXMWhkR2xyYVc1bWNtRnpkSEoxYTNSMWNqRWdNQjRHQTFVRUF3d1hSMFZOTGxOTlEwSXRRMEUxTVNCVVJWTlVMVTlPVEZrd0hoY05NalF3TWpJM01EQXdNREF3V2hjTk1qa3dNakkzTWpNMU9UVTVXakNCeFRFTE1Ba0dBMVVFQmhNQ1JFVXhIREFhQmdOVkJBZ01FMDV2Y21SeWFHVnBiaTFYWlhOMFptRnNaVzR4RWpBUUJnTlZCQWNNQ1VKcFpXeGxabVZzWkRFT01Bd0dBMVVFRVF3Rk16TTJNREl4SHpBZEJnTlZCQWtNRmtKaFkydHdkV3gyWlhKZlUzUnlZWE56WlY4M056Y3hLakFvQmdOVkJBb01JVE10TWkxRlVFRXRPRE16TmpJeE9UazVOelF4TmpBd0lFNVBWQzFXUVV4SlJERW5NQ1VHQTFVRUF3d2VRWE5qYUc5bVpuTmphR1VnUVhCdmRHaGxhMlVnVkVWVFZDMVBUa3haTUZvd0ZBWUhLb1pJemowQ0FRWUpLeVFEQXdJSUFRRUhBMElBQktUalY5RjhEUks2aGtpNTkxbE01U2JzSC9ScTd4OEtPUWhqcG9ZYUlzc2poN3BEWHg5cWV2d01QR1Z1L3ZDVEJyeXd1T3VIU0pUNHgzbXZGdlQrSCtHamdnR3RNSUlCcVRCMkJnVXJKQWdEQXdSdE1HdWtLREFtTVFzd0NRWURWUVFHRXdKRVJURVhNQlVHQTFVRUNnd09RVXNnUW5KaGJtUmxibUoxY21jd1B6QTlNRHN3T1RBWERCWERsbVptWlc1MGJHbGphR1VnUVhCdmRHaGxhMlV3Q1FZSEtvSVVBRXdFTmhNVE15MHlMak16TXpNNU9DNVVaWE4wVDI1c2VUQTdCZ2dyQmdFRkJRY0JBUVF2TUMwd0t3WUlLd1lCQlFVSE1BR0dIMmgwZEhBNkx5OWxhR05oTG1kbGJXRjBhV3N1WkdVdlpXTmpMVzlqYzNBd0lRWURWUjBSQkJvd0dLQVdCZ05WQkFPZ0R3d05UMlYwYTJWeUxVZHlkWEJ3WlRBZEJnTlZIUTRFRmdRVWh0WWN2UlVLZnpRdTRKNXJ4UjYzaDBheG5Id3dFd1lEVlIwbEJBd3dDZ1lJS3dZQkJRVUhBd0l3WEFZRFZSMGdCRlV3VXpBN0JnZ3FnaFFBVEFTQkl6QXZNQzBHQ0NzR0FRVUZCd0lCRmlGb2RIUndPaTh2ZDNkM0xtZGxiV0YwYVdzdVpHVXZaMjh2Y0c5c2FXTnBaWE13Q1FZSEtvSVVBRXdFVFRBSkJnY3FnaFFBVEFSbE1COEdBMVVkSXdRWU1CYUFGQWFZNlFKVi84bWZYS05sRHZGZDRpRDFoUHVUTUE0R0ExVWREd0VCL3dRRUF3SUhnREFNQmdOVkhSTUJBZjhFQWpBQU1Bb0dDQ3FHU000OUJBTUNBMGdBTUVVQ0lFMjRsUzF2TG5BVUtkVjIvK3ZiYzVUUGFrM05TZXYxVGRteExFMUVkQm1xQWlFQWh6TzdHUCtKQTY1NDN2Z0R5cnNxeXF6d0JXZkYzSkdRZ2pwUk5iZEVKRlE9Il0sImFsZyI6IkVTMjU2In0.eyJub25jZSI6IjEzZGM4YTliNmE1OGI2NWRiM2I3NWM1YzVkMDhmMzY2MDVhOGY3YWI2NDg4NTgyY2QyMjZjODlkYTY1MTgyYTYiLCJpYXQiOjE3MTg2MDU0MDZ9.KI7LEuI9Ez0SgI-wZNVvNtzXg_xx5W7ABbHeJCdV5GUoESvs7p4FnFxnPSIMCMRiW7N5Q6yCPRJE4eVXxB6irQ"))
        .isTrue();
  }

  @Test
  void isBase64UR_clientAttest_invalidBase64() {
    assertThat(
            Base64UrlValidator.isBase64URL(
                "eyJ0eXAiOiJKV1QiLCJ4NWMiOlsiTUlJRUJqQ0NBNnlnQXdJQkFnSUhBU3VvQUZaMCt6QUtCZ2dxaGtqT1BRUURBakNCbWpFTE1Ba0dBMVVFQmhNQ1JFVXhIekFkQmdOVkJBb01GbWRsYldGMGFXc2dSMjFpU0NCT1QxUXRWa0ZNU1VReFNEQkdCZ05WQkFzTVAwbHVjM1JwZEhWMGFXOXVJR1JsY3lCSFpYTjFibVJvWldsMGMzZGxjMlZ1Y3kxRFFTQmtaWElnVkdWc1pXMWhkR2xyYVc1bWNtRnpkSEoxYTNSMWNqRWdNQjRHQTFVRUF3d1hSMFZOTGxOTlEwSXRRMEUxTVNCVVJWTlVMVTlPVEZrd0hoY05NalF3TWpJM01EQXdNREF3V2hjTk1qa3dNakkzTWpNMU9UVTVXakNCeFRFTE1Ba0dBMVVFQmhNQ1JFVXhIREFhQmdOVkJBZ01FMDV2Y21SeWFHVnBiaTFYWlhOMFptRnNaVzR4RWpBUUJnTlZCQWNNQ1VKcFpXeGxabVZzWkRFT01Bd0dBMVVFRVF3Rk16TTJNREl4SHpBZEJnTlZCQWtNRmtKaFkydHdkV3gyWlhKZlUzUnlZWE56WlY4M056Y3hLakFvQmdOVkJBb01JVE10TWkxRlVFRXRPRE16TmpJeE9UazVOelF4TmpBd0lFNVBWQzFXUVV4SlJERW5NQ1VHQTFVRUF3d2VRWE5qYUc5bVpuTmphR1VnUVhCdmRHaGxhMlVnVkVWVFZDMVBUa3haTUZvd0ZBWUhLb1pJemowQ0FRWUpLeVFEQXdJSUFRRUhBMElBQktUalY5RjhEUks2aGtpNTkxbE01U2JzSC9ScTd4OEtPUWhqcG9ZYUlzc2poN3BEWHg5cWV2d01QR1Z1L3ZDVEJyeXd1T3VIU0pUNHgzbXZGdlQrSCtHamdnR3RNSUlCcVRCMkJnVXJKQWdEQXdSdE1HdWtLREFtTVFzd0NRWURWUVFHRXdKRVJURVhNQlVHQTFVRUNnd09RVXNnUW5KaGJtUmxibUoxY21jd1B6QTlNRHN3T1RBWERCWERsbVptWlc1MGJHbGphR1VnUVhCdmRHaGxhMlV3Q1FZSEtvSVVBRXdFTmhNVE15MHlMak16TXpNNU9DNVVaWE4wVDI1c2VUQTdCZ2dyQmdFRkJRY0JBUVF2TUMwd0t3WUlLd1lCQlFVSE1BR0dIMmgwZEhBNkx5OWxhR05oTG1kbGJXRjBhV3N1WkdVdlpXTmpMVzlqYzNBd0lRWURWUjBSQkJvd0dLQVdCZ05WQkFPZ0R3d05UMlYwYTJWeUxVZHlkWEJ3WlRBZEJnTlZIUTRFRmdRVWh0WWN2UlVLZnpRdTRKNXJ4UjYzaDBheG5Id3dFd1lEVlIwbEJBd3dDZ1lJS3dZQkJRVUhBd0l3WEFZRFZSMGdCRlV3VXpBN0JnZ3FnaFFBVEFTQkl6QXZNQzBHQ0NzR0FRVUZCd0lCRmlGb2RIUndPaTh2ZDNkM0xtZGxiV0YwYVdzdVpHVXZaMjh2Y0c5c2FXTnBaWE13Q1FZSEtvSVVBRXdFVFRBSkJnY3FnaFFBVEFSbE1COEdBMVVkSXdRWU1CYUFGQWFZNlFKVi84bWZYS05sRHZGZDRpRDFoUHVUTUE0R0ExVWREd0VCL3dRRUF3SUhnREFNQmdOVkhSTUJBZjhFQWpBQU1Bb0dDQ3FHU000OUJBTUNBMGdBTUVVQ0lFMjRsUzF2TG5BVUtkVjIvK3ZiYzVUUGFrM05TZXYxVGRteExFMUVkQm1xQWlFQWh6TzdHUCtKQTY1NDN2Z0R5cnNxeXF6d0JXZkYzSkdRZ2pwUk5iZEVKRlE9Il0sImFsZyI6IkVTMjU2In0.eyJub25jZSI6IjIyYTllOWVhODRhNWJkNWI0N2IxODA3MWIxNTcwMWJmNjVmMDJlN2Y2ZWQ5OGU0ZmIxYzc2Zjc3MzliODMyMDkiLCJpYXQiOjE3MTg2MDUxMjF9.CTmEIabsM+Cm16Qf93mTeu27r2LA+trz4wNH1OsC0qg1NCBFeHY4GO3Y4tqXFMnnlCCUdhkolVTEjljpZZZXqQ=="))
        .isFalse();
  }
}
