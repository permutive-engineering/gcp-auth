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

package com.permutive.gcp.auth

import java.security.KeyFactory
import java.security.interfaces.RSAPrivateKey
import java.security.spec.PKCS8EncodedKeySpec
import java.util.Base64
import java.util.regex.Pattern

import cats.effect.Concurrent
import cats.effect.Sync
import cats.syntax.all._

import com.permutive.gcp.auth.errors.EmptyRefreshTokenFile
import com.permutive.gcp.auth.errors.UnableToGetClientData
import com.permutive.gcp.auth.errors.UnableToGetClientSecrets
import com.permutive.gcp.auth.errors.UnableToGetDefaultCredentials
import com.permutive.gcp.auth.models.ClientEmail
import com.permutive.gcp.auth.models.ClientId
import com.permutive.gcp.auth.models.ClientSecret
import com.permutive.gcp.auth.models.RefreshToken
import fs2.io.file.Files
import fs2.io.file.Path
import io.circe.Decoder
import io.circe.parser

private[auth] object Parser {

  final def googleRefreshToken[F[_]: Files: Concurrent](path: Path): F[RefreshToken] =
    Files[F]
      .readUtf8Lines(path)
      .head
      .compile
      .onlyOrError
      .map(line => RefreshToken(line.trim()))
      .adaptError { case _ => new EmptyRefreshTokenFile(path) }

  final def googleClientSecrets[F[_]: Files: Concurrent](path: Path): F[(ClientId, ClientSecret)] =
    Files[F]
      .readUtf8(path)
      .compile
      .string
      .flatMap(parser.parse(_).liftTo[F])
      .map(_.hcursor.downField("installed"))
      .flatMap { installed =>
        (installed.get[ClientId]("client_id"), installed.get[ClientSecret]("client_secret")).tupled.liftTo[F]
      }
      .adaptError { case t => new UnableToGetClientSecrets(path, t) }

  final def googleServiceAccount[F[_]: Files: Sync](path: Path): F[(ClientEmail, RSAPrivateKey)] =
    Files[F]
      .readUtf8(path)
      .compile
      .string
      .flatMap(parser.parse(_).liftTo[F])
      .flatMap { json =>
        (json.hcursor.get[ClientEmail]("client_email"), json.hcursor.get[String]("private_key")).tupled.liftTo[F]
      }
      .flatMap(_.traverse(loadPrivateKey[F]))
      .adaptError { case t => new UnableToGetClientData(path, t) }

  final def applicationDefaultCredentials[F[_]: Concurrent: Files]: F[(ClientId, ClientSecret, RefreshToken)] =
    Files[F]
      .readUtf8(defaultCredentialsFile)
      .compile
      .string
      .flatMap(parser.decode[(ClientId, ClientSecret, RefreshToken)](_).liftTo[F])
      .adaptError { case t => new UnableToGetDefaultCredentials(defaultCredentialsFile, t) }

  implicit private val decodeCredentials: Decoder[(ClientId, ClientSecret, RefreshToken)] = c =>
    (c.get[ClientId]("client_id"), c.get[ClientSecret]("client_secret"), c.get[RefreshToken]("refresh_token")).tupled

  /** Load application default credentials from `~/.config/cloud/application_default_credentials.json` create this file
    * with `gcloud auth application-default login`, or set `GOOGLE_APPLICATION_CREDENTIALS` to override to another path
    */
  private def defaultCredentialsFile: Path = sys.env.get("GOOGLE_APPLICATION_CREDENTIALS").map(Path(_)).getOrElse {
    val os = sys.props.getOrElse("os.name", "").toLowerCase()

    if (os.indexOf("windows") >= 0)
      Path(sys.env("APPDATA")) / "gcloud" / "application_default_credentials.json"
    else
      Path(sys.props.getOrElse("user.home", "")) / ".config" / "gcloud" / "application_default_credentials.json"
  }

  private[this] val privateKeyPattern = Pattern.compile("(?m)(?s)^---*BEGIN.*---*$(.*)^---*END.*---*$.*")

  private def loadPrivateKey[F[_]: Sync](pem: String): F[RSAPrivateKey] =
    Sync[F].blocking {
      val encoded = privateKeyPattern.matcher(pem).replaceFirst("$1")

      val decoded = Base64.getMimeDecoder.decode(encoded.trim())
      val spec    = new PKCS8EncodedKeySpec(decoded)

      KeyFactory.getInstance("RSA").generatePrivate(spec).asInstanceOf[RSAPrivateKey]
    }

}
