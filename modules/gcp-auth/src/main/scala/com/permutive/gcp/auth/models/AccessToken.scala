/*
 * Copyright 2024 Permutive Engineering <https://permutive.com>
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

import cats.effect.Concurrent
import cats.syntax.all._

import io.circe.Decoder
import org.http4s.AuthScheme
import org.http4s.Credentials
import org.http4s.EntityDecoder
import org.http4s.circe.jsonOf
import org.http4s.headers.Authorization

sealed abstract class AccessToken(val token: Token, val expiresIn: ExpiresIn) extends Serializable {

  @SuppressWarnings(Array("scalafix:Disable.toString"))
  override def toString(): String = show"AccessToken(token=REDACTED,expiresIn=$expiresIn"

  @SuppressWarnings(Array("scalafix:Disable.equals"))
  override def equals(obj: Any): Boolean = obj match {
    case a: AccessToken => a.token === token && a.expiresIn === expiresIn
    case _              => false
  }

  def asHeader: Authorization = Authorization(Credentials.Token(AuthScheme.Bearer, token))

}

object AccessToken {

  def apply(token: Token, expiresIn: ExpiresIn): AccessToken = new AccessToken(token, expiresIn) {}

  lazy val noop = new AccessToken(Token("noop"), ExpiresIn(3600)) {}

  implicit val AccessTokenDecoder: Decoder[AccessToken] =
    Decoder.forProduct2[AccessToken, Token, ExpiresIn]("access_token", "expires_in") { (token, expiresIn) =>
      new AccessToken(token, expiresIn) {}
    }

  implicit def AccessTokenEntityDecoder[F[_]: Concurrent]: EntityDecoder[F, AccessToken] = jsonOf[F, AccessToken]

}
