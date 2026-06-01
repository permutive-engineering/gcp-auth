/*
 * Copyright 2024-2025 Permutive Ltd. <https://permutive.com>
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

package com.permutive.gcp.auth.models

import java.time.Instant

import cats.effect.Clock
import cats.effect.Concurrent
import cats.syntax.all._

import io.circe.Decoder
import org.http4s.AuthScheme
import org.http4s.Credentials
import org.http4s.DecodeResult
import org.http4s.EntityDecoder
import org.http4s.circe.jsonOf
import org.http4s.headers.Authorization

sealed abstract class AccessToken(val token: Token, val expiresIn: ExpiresIn, val expiresAt: Instant)
    extends Serializable {

  override def toString(): String = s"AccessToken(token=REDACTED,expiresIn=$expiresIn,expiresAt=$expiresAt)"

  override def equals(obj: Any): Boolean = obj match {
    case a: AccessToken => a.token === token && a.expiresIn === expiresIn && a.expiresAt.equals(expiresAt)
    case _              => false
  }

  override def hashCode(): Int = (token, expiresIn, expiresAt).hashCode()

  def asHeader: Authorization = Authorization(Credentials.Token(AuthScheme.Bearer, token.value))

}

object AccessToken {

  /** Constructs an `AccessToken` from a token value, its lifetime (seconds-of-validity from Google), and its absolute
    * deadline.
    *
    * Callers are responsible for keeping `expiresIn` and `expiresAt` consistent — `expiresAt` should equal "fetch time
    * + expiresIn". The wire-format entity decoder and the in-tree factories do this for you.
    */
  def apply(token: Token, expiresIn: ExpiresIn, expiresAt: Instant): AccessToken =
    new AccessToken(token, expiresIn, expiresAt) {}

  def unapply(token: AccessToken): Some[(Token, ExpiresIn, Instant)] =
    Some((token.token, token.expiresIn, token.expiresAt))

  /** A sentinel access token whose deadline is set far enough in the future that it will never expire in practice.
    * Intended for tests and no-op token providers — not a valid Google token.
    */
  lazy val noop: AccessToken = AccessToken(Token("noop"), ExpiresIn(3600), Instant.MAX)

  /** Wire format Google sends back from its OAuth endpoints. Used only by [[AccessTokenEntityDecoder]] to recover the
    * `expires_in` relative duration so the absolute deadline can be fixed against the current clock.
    */
  private case class Response(token: Token, expiresIn: ExpiresIn)

  implicit private val ResponseDecoder: Decoder[Response] =
    Decoder
      .forProduct2("access_token", "expires_in")(Response.apply)
      .or(Decoder.forProduct2("id_token", "expires_in")(Response.apply))

  /** Decodes Google's `(access_token, expires_in)` response and fixes the absolute deadline at decode time using the
    * current clock — so the resulting `expiresAt` does not drift if the token is cached and re-read later.
    */
  implicit def AccessTokenEntityDecoder[F[_]: Concurrent: Clock]: EntityDecoder[F, AccessToken] =
    jsonOf[F, Response].flatMapR { response =>
      DecodeResult.success {
        Clock[F].realTimeInstant.map(now =>
          AccessToken(response.token, response.expiresIn, now.plusSeconds(response.expiresIn.value))
        )
      }
    }

}
