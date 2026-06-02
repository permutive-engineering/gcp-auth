/*
 * Copyright 2024-2026 Permutive Ltd. <https://permutive.com>
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

package com.permutive.gcp.auth.kafka

import java.nio.charset.StandardCharsets.UTF_8
import java.time.Instant
import java.util.Base64

import scala.jdk.CollectionConverters._

import com.permutive.gcp.auth.models.AccessToken
import com.permutive.gcp.auth.models.ExpiresIn
import com.permutive.gcp.auth.models.Token
import io.circe.parser
import munit.FunSuite
import org.apache.kafka.common.security.auth.SaslExtensionsCallback

class GcpLoginCallbackHandlerSuite extends FunSuite {

  test("buildKafkaToken produces the GOOG_OAUTH2_TOKEN envelope") {
    val handler = new GcpLoginCallbackHandler

    val expiresAt = Instant.now().plusSeconds(3600)

    val before = Instant.now().getEpochSecond
    val token  = handler.buildKafkaToken(
      () => AccessToken(Token("the-google-token"), ExpiresIn(3600), expiresAt),
      "sa@x.iam.gserviceaccount.com"
    )
    val after = Instant.now().getEpochSecond

    val segments = token.value().split('.')
    assertEquals(segments.length, 3, s"expected three dot-separated segments, got: ${token.value()}")

    val headerB64    = segments(0)
    val payloadB64   = segments(1)
    val signatureB64 = segments(2)

    val header = new String(Base64.getUrlDecoder.decode(headerB64), UTF_8)
    assertEquals(header, """{"typ":"JWT","alg":"GOOG_OAUTH2_TOKEN"}""")

    val payloadJson = new String(Base64.getUrlDecoder.decode(payloadB64), UTF_8)
    val payload     = parser.parse(payloadJson).toOption.flatMap(_.asObject).getOrElse(fail("payload is not a JSON object"))

    assertEquals(payload("scope").flatMap(_.asString), Some("kafka"))
    assertEquals(payload("sub").flatMap(_.asString), Some("sa@x.iam.gserviceaccount.com"))

    val iat = payload("iat").flatMap(_.asNumber).flatMap(_.toLong).getOrElse(fail("iat is missing"))
    val exp = payload("exp").flatMap(_.asNumber).flatMap(_.toLong).getOrElse(fail("exp is missing"))

    assert(iat >= before && iat <= after, s"iat=$iat should be between $before and $after")
    assertEquals(exp, expiresAt.getEpochSecond)

    val signature = new String(Base64.getUrlDecoder.decode(signatureB64), UTF_8)
    assertEquals(signature, "the-google-token")
  }

  test("buildKafkaToken sets BasicOAuthBearerToken fields") {
    val handler = new GcpLoginCallbackHandler

    val expiresAt = Instant.now().plusSeconds(3600)

    val token =
      handler.buildKafkaToken(() => AccessToken(Token("tok"), ExpiresIn(3600), expiresAt), "principal@example.com")

    assertEquals(token.scope().asScala.toSet, Set("kafka"))
    assertEquals(token.principalName(), "principal@example.com")
    assertEquals(token.lifetimeMs(), expiresAt.getEpochSecond * 1000L)
  }

  test("configure rejects non-OAUTHBEARER mechanisms") {
    val handler = new GcpLoginCallbackHandler

    intercept[IllegalArgumentException] {
      handler.configure(new java.util.HashMap[String, AnyRef], "PLAIN", java.util.Collections.emptyList())
    }
  }

  test("handle before configure throws IllegalStateException") {
    val handler = new GcpLoginCallbackHandler

    intercept[IllegalStateException] {
      handler.handle(Array(new SaslExtensionsCallback))
    }
  }

}
