/*
 *  Copyright 2024, gematik GmbH
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
 *
 * *******
 *
 * For additional notes and disclaimer from gematik and in case of changes by gematik find details in the "Readme" file.
 */

package de.gematik.idp.asforepa.test.steps;

import de.gematik.test.tiger.common.config.TigerGlobalConfiguration;
import groovy.util.logging.Slf4j;
import io.cucumber.java.en.And;
import net.serenitybdd.annotations.Steps;

@Slf4j
public class StepsGlue {
  @Steps AsforepaSteps asforepaSteps;

  @And("generate client attest from nonce {tigerResolvedString} and save as clientAttest")
  public void generateClientAttestFromNonce(final String nonce) {
    final String clientAttest = asforepaSteps.generateClientAttestFromNonce(nonce);
    TigerGlobalConfiguration.putValue("clientAttest", clientAttest);
  }
}
