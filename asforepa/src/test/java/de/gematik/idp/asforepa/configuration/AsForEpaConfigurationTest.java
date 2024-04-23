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

package de.gematik.idp.asforepa.configuration;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.core.io.ResourceLoader;

@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
class AsForEpaConfigurationTest {

  @Autowired de.gematik.idp.asforepa.configuration.AsForEpaConfiguration asForEpaConfiguration;
  @Autowired ResourceLoader resourceLoader;

  @Test
  void fullIntTestComponent() {
    assertThat(asForEpaConfiguration).isNotNull();
    assertThat(asForEpaConfiguration.getServerUrl()).isNotNull();
    assertThat(asForEpaConfiguration.getRedirectUri()).isNotNull();
    assertThat(asForEpaConfiguration.getScopes()).isNotEmpty();
  }

  @Test
  void testBuildComponent() {
    final AsForEpaConfiguration rasConfig =
        AsForEpaConfiguration.builder().serverUrl("serverurl").clientId("dummyClient").build();
    rasConfig.setServerUrl("newUrl");
    assertThat(rasConfig).isNotNull();
    assertThat(rasConfig.getServerUrl()).isEqualTo("newUrl");
    assertThat(rasConfig.toString()).hasSizeGreaterThan(0);
    assertThat(rasConfig).isNotEqualTo(asForEpaConfiguration);

    assertThat(AsForEpaConfiguration.builder().toString()).hasSizeGreaterThan(0);
    final AsForEpaConfiguration rasConfig2 = rasConfig;
    assertThat(rasConfig).isEqualTo(rasConfig2);
  }
}
