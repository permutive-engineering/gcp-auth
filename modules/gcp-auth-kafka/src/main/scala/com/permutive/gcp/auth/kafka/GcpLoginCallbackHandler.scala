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
import java.{util => j}

import scala.jdk.CollectionConverters._

import cats.effect.IO
import cats.effect.std.Dispatcher
import cats.effect.unsafe.implicits.global
import cats.syntax.all._

import com.permutive.gcp.auth.TokenProvider
import com.permutive.gcp.auth.models.AccessToken
import io.circe.Json
import io.circe.syntax._
import javax.security.auth.callback.Callback
import javax.security.auth.callback.UnsupportedCallbackException
import javax.security.auth.login.AppConfigurationEntry
import org.apache.kafka.common.security.auth.AuthenticateCallbackHandler
import org.apache.kafka.common.security.auth.SaslExtensions
import org.apache.kafka.common.security.auth.SaslExtensionsCallback
import org.apache.kafka.common.security.oauthbearer.OAuthBearerTokenCallback
import org.apache.kafka.common.security.oauthbearer.internals.secured.BasicOAuthBearerToken

/** Kafka SASL/OAUTHBEARER login callback handler for Google Managed Service for Apache Kafka.
  *
  * Drop-in replacement for Google's `com.google.cloud.hosted.kafka.auth.GcpLoginCallbackHandler` that uses `gcp-auth`'s
  * [[com.permutive.gcp.auth.TokenProvider TokenProvider]] under the hood — no `kafka-schema-registry-client`, no Google
  * Java SDK on the classpath.
  *
  * Wire it into your Kafka client config:
  * {{{
  * security.protocol                 = SASL_SSL
  * sasl.mechanism                    = OAUTHBEARER
  * sasl.login.callback.handler.class = com.permutive.gcp.auth.kafka.GcpLoginCallbackHandler
  * sasl.jaas.config                  = org.apache.kafka.common.security.oauthbearer.OAuthBearerLoginModule required;
  * }}}
  *
  * The handler resolves credentials via `TokenProvider.auto` (ADC precedence). The `sub` claim is taken from
  * `GOOGLE_MANAGED_KAFKA_AUTH_PRINCIPAL` when set (overrides the provider's principal — useful for Workforce Identity
  * Federation cases), otherwise from the provider's `principal`. If neither yields a value, [[configure]] raises an
  * `IllegalStateException` pointing at the env var.
  */
@SuppressWarnings(Array("scalafix:DisableSyntax.var", "scalafix:DisableSyntax.throw"))
class GcpLoginCallbackHandler extends AuthenticateCallbackHandler {

  /** Returns a fresh access token on each call. Populated by [[configure]] — it bakes in the cached `TokenProvider`
    * plus the dispatcher so [[handle]] can synchronously cross the cats-effect / Kafka SPI boundary.
    */
  private var fetchToken: () => AccessToken = _

  /** Subject identifier baked in at [[configure]] time and used as the `sub` claim of every emitted token. Resolved
    * once from `GOOGLE_MANAGED_KAFKA_AUTH_PRINCIPAL` when set (overrides the provider's principal), otherwise from the
    * provider's `principal`. If neither yields a value, [[configure]] raises an `IllegalStateException`.
    */
  private var sub: String = _

  /** Finaliser that releases the resources allocated in [[configure]] (the dispatcher, the JDK http client, and the
    * cached token-refresh fiber). Run from [[close]].
    */
  private var release: IO[Unit] = IO.unit

  /** Set once [[configure]] succeeds. [[handle]] checks this and raises `IllegalStateException` when called first —
    * matches the contract of Google's `GcpLoginCallbackHandler`.
    */
  private var configured: Boolean = false

  override def configure(configs: j.Map[String, _], mechanism: String, entries: j.List[AppConfigurationEntry]) = {
    require(mechanism === "OAUTHBEARER", s"Unexpected SASL mechanism: $mechanism")

    val resources = for {
      dispatcher <- Dispatcher.parallel[IO]
      provider   <- TokenProvider.auto[IO].flatMap(TokenProvider.cached[IO].build(_))
    } yield {
      fetchToken = () => dispatcher.unsafeRunSync(provider.accessToken)

      sub = sys.env.get("GOOGLE_MANAGED_KAFKA_AUTH_PRINCIPAL").filter(_.nonEmpty).getOrElse {
        dispatcher.unsafeRunSync(provider.principal).getOrElse {
          throw new IllegalStateException(
            "Unable to determine principal for credentials. " +
              "Please set the GOOGLE_MANAGED_KAFKA_AUTH_PRINCIPAL environment variable."
          )
        }
      }
    }

    release = resources.allocated.unsafeRunSync()._2
    configured = true
  }

  override def handle(callbacks: Array[Callback]): Unit = {
    if (!configured) throw new IllegalStateException("Callback handler not configured")

    callbacks.foreach {
      case cb: OAuthBearerTokenCallback => cb.token(buildKafkaToken(fetchToken, sub))
      case cb: SaslExtensionsCallback   => cb.extensions(SaslExtensions.empty())
      case other                        => throw new UnsupportedCallbackException(other)
    }
  }

  override def close(): Unit = release.unsafeRunSync()

  private[kafka] def buildKafkaToken(fetchToken: () => AccessToken, sub: String): BasicOAuthBearerToken = {
    val token = fetchToken()

    val now    = Instant.now()
    val expSec = token.expiresAt.getEpochSecond

    val header  = Json.obj("typ" := "JWT", "alg" := "GOOG_OAUTH2_TOKEN")
    val payload = Json.obj("exp" := expSec, "iat" := now.getEpochSecond, "scope" := "kafka", "sub" := sub)

    val envelope = Seq(header.noSpaces, payload.noSpaces, token.token.value)
      .map(_.getBytes(UTF_8))
      .map(Base64.getUrlEncoder.withoutPadding.encodeToString)
      .mkString(".")

    new BasicOAuthBearerToken(envelope, Set("kafka").asJava, expSec * 1000L, sub, now.toEpochMilli)
  }

}
