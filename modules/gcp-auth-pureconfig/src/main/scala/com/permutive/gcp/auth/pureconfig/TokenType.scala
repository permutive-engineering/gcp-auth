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

package com.permutive.gcp.auth.pureconfig

import cats.effect.Concurrent
import cats.syntax.all._

import _root_.pureconfig.ConfigReader
import com.permutive.gcp.auth.TokenProvider
import com.permutive.gcp.auth.models.AccessToken
import fs2.io.file.Files
import org.http4s.client.Client

/** Provides a convenient way to initialise a [[com.permutive.gcp.auth.TokenProvider TokenProvider]] using pureconfig.
  *
  * Allowed values when reading from configuration files are `user-account`, `service-account` and `no-op`. Check
  * [[TokenType.tokenProvider]] for more information on how a [[com.permutive.gcp.auth.TokenProvider TokenProvider]] is
  * created from these values.
  */
sealed trait TokenType {

  /** Creates a [[com.permutive.gcp.auth.TokenProvider TokenProvider]] using a different method depending on the
    * instance:
    *
    *   - [[TokenType.UserAccount]]: the provider will be created using `TokenProvider.userAccount`.
    *   - [[TokenType.ServiceAccount]]: the provider will be created using `TokenProvider.serviceAccount`.
    *   - [[TokenType.NoOp]]: will return a provider that always returns
    *     [[com.permutive.gcp.auth.models.AccessToken.noop AccessToken.noop]].
    */
  def tokenProvider[F[_]: Files: Concurrent](httpClient: Client[F]): F[TokenProvider[F]] = this match {
    case TokenType.UserAccount    => TokenProvider.userAccount[F](httpClient)
    case TokenType.ServiceAccount => TokenProvider.serviceAccount[F](httpClient).pure[F]
    case TokenType.NoOp           => TokenProvider.const(AccessToken.noop).pure[F]
  }

}

object TokenType {

  case object UserAccount extends TokenType

  case object ServiceAccount extends TokenType

  case object NoOp extends TokenType

  implicit val TokenTypeConfigReader: ConfigReader[TokenType] = ConfigReader.fromStringOpt {
    case "user-account"    => TokenType.UserAccount.some
    case "service-account" => TokenType.ServiceAccount.some
    case "no-op"           => TokenType.NoOp.some
  }

}
