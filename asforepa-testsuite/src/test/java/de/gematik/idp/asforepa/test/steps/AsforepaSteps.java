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

package de.gematik.idp.asforepa.test.steps;

import static org.jose4j.jws.EcdsaUsingShaAlgorithm.convertDerToConcatenated;

import de.gematik.idp.crypto.CryptoLoader;
import de.gematik.idp.crypto.EcSignerUtility;
import de.gematik.idp.crypto.RsaSignerUtility;
import de.gematik.idp.crypto.model.PkiIdentity;
import de.gematik.idp.field.ClaimName;
import de.gematik.idp.token.JsonWebToken;
import groovy.util.logging.Slf4j;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.security.interfaces.RSAPrivateKey;
import java.time.ZonedDateTime;
import java.util.Base64;
import java.util.function.UnaryOperator;
import lombok.SneakyThrows;
import org.apache.commons.io.FileUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;

@Slf4j
public class AsforepaSteps {

  static {
    Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
    Security.insertProviderAt(new BouncyCastleProvider(), 1);
  }

  @SneakyThrows
  public String generateClientAttestFromNonce(final String nonce) {
    final byte[] p12FileContent =
        FileUtils.readFileToByteArray(
            new File("src/test/resources/833621999741600-2_c.hci.aut-apo-ecc.p12"));
    final PkiIdentity smcbIdentityEcc = CryptoLoader.getIdentityFromP12(p12FileContent, "00");
    final JwtClaims claims = new JwtClaims();
    claims.setClaim(ClaimName.NONCE.getJoseName(), nonce);
    claims.setClaim(ClaimName.ISSUED_AT.getJoseName(), ZonedDateTime.now().toEpochSecond());
    final JsonWebSignature jsonWebSignature = new JsonWebSignature();
    jsonWebSignature.setPayload(claims.toJson());
    jsonWebSignature.setHeader("typ", "JWT");
    jsonWebSignature.setCertificateChainHeaderValue(smcbIdentityEcc.getCertificate());
    jsonWebSignature.setAlgorithmHeaderValue(
        AlgorithmIdentifiers.ECDSA_USING_P256_CURVE_AND_SHA256);
    jsonWebSignature.setKey(smcbIdentityEcc.getPrivateKey());
    final String signedJwt =
        jsonWebSignature.getHeaders().getEncodedHeader()
            + "."
            + jsonWebSignature.getEncodedPayload()
            + "."
            + Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(
                    getSignatureBytes(
                        getContentSigner(smcbIdentityEcc),
                        jsonWebSignature,
                        sigData -> {
                          try {
                            return convertDerToConcatenated(sigData, 64);
                          } catch (final IOException e) {
                            throw new RuntimeException(e);
                          }
                        }));
    return new JsonWebToken(signedJwt).getRawString();
  }

  private byte[] getSignatureBytes(
      final UnaryOperator<byte[]> contentSigner,
      final JsonWebSignature jsonWebSignature,
      final UnaryOperator<byte[]> signatureStripper) {
    return signatureStripper.apply(
        contentSigner.apply(
            (jsonWebSignature.getHeaders().getEncodedHeader()
                    + "."
                    + jsonWebSignature.getEncodedPayload())
                .getBytes(StandardCharsets.UTF_8)));
  }

  private static UnaryOperator<byte[]> getContentSigner(final PkiIdentity pkiIdentity) {
    return tbsData -> {
      if (pkiIdentity.getPrivateKey() instanceof RSAPrivateKey) {
        return RsaSignerUtility.createRsaSignature(tbsData, pkiIdentity.getPrivateKey());
      } else {
        return EcSignerUtility.createEcSignature(tbsData, pkiIdentity.getPrivateKey());
      }
    };
  }
}
