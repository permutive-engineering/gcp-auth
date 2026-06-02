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

package com.permutive.gcp.auth

import java.security.KeyFactory
import java.security.interfaces.RSAPrivateKey
import java.security.spec.PKCS8EncodedKeySpec
import java.util.Base64
import java.util.regex.Pattern

import cats.effect.Concurrent
import cats.effect.Sync
import cats.syntax.all._

import com.permutive.gcp.auth.Parser.CredentialsFile.ServiceAccount
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
import io.circe.DecodingFailure
import io.circe.parser

private[auth] object Parser {

  /** Parsed contents of a Google "Application Default Credentials" JSON file. Restricted to the two file types that
    * `TokenProvider.auto` can consume directly: `service_account` and `authorized_user`.
    */
  sealed trait CredentialsFile

  object CredentialsFile {

    implicit lazy val CredentialsFileDecoder: Decoder[CredentialsFile] = cursor =>
      cursor.get[String]("type").flatMap {
        case "service_account" => cursor.as[CredentialsFile.ServiceAccount]
        case "authorized_user" => cursor.as[CredentialsFile.AuthorizedUser]
        case other             => DecodingFailure(s"Unsupported credentials file type: $other", cursor.history).asLeft
      }

    final case class ServiceAccount(clientEmail: ClientEmail, privateKey: RSAPrivateKey) extends CredentialsFile

    object ServiceAccount {

      private[this] val privateKeyPattern = Pattern.compile("(?m)(?s)^---*BEGIN.*---*$(.*)^---*END.*---*$.*")

      /** Decoder for a PEM-encoded RSA private key (e.g. the `private_key` field of a service-account JSON). Decoding
        * failures (malformed PEM, bad Base64, bad PKCS8) bubble up as `DecodingFailure`.
        */
      implicit lazy val RSAPrivateKeyDecoder: Decoder[RSAPrivateKey] = Decoder[String].emap { pem =>
        Either.catchNonFatal {
          val encoded = privateKeyPattern.matcher(pem).replaceFirst("$1")
          val decoded = Base64.getMimeDecoder.decode(encoded.trim())
          val spec    = new PKCS8EncodedKeySpec(decoded)

          KeyFactory.getInstance("RSA").generatePrivate(spec).asInstanceOf[RSAPrivateKey]
        }.leftMap(t => s"Invalid private key: ${t.getMessage}")
      }

      implicit lazy val ServiceAccountDecoder: Decoder[ServiceAccount] =
        Decoder.forProduct2("client_email", "private_key")(ServiceAccount.apply)

    }

    final case class AuthorizedUser(clientId: ClientId, clientSecret: ClientSecret, refreshToken: RefreshToken)
        extends CredentialsFile

    object AuthorizedUser {

      implicit lazy val AuthorizedUserDecoder: Decoder[AuthorizedUser] =
        Decoder.forProduct3("client_id", "client_secret", "refresh_token")(AuthorizedUser.apply)

    }

  }

  /** Reads a refresh token from the first non-empty line of a plain-text file.
    *
    * Raises [[com.permutive.gcp.auth.errors.EmptyRefreshTokenFile EmptyRefreshTokenFile]] when the file is empty (no
    * line to consume).
    */
  final def googleRefreshToken[F[_]: Files: Concurrent](path: Path): F[RefreshToken] =
    Files[F]
      .readUtf8Lines(path)
      .head
      .compile
      .onlyOrError
      .map(line => RefreshToken(line.trim()))
      .adaptError { case _ => new EmptyRefreshTokenFile(path) }

  /** Parses a Google OAuth "client secrets" JSON file (as produced by `gcloud` or downloaded from the Cloud Console)
    * and extracts the `client_id` and `client_secret` fields from its top-level `installed` object.
    *
    * Raises [[com.permutive.gcp.auth.errors.UnableToGetClientSecrets UnableToGetClientSecrets]] if the file cannot be
    * read, the JSON does not parse, or the required fields are missing.
    */
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

  /** Parses a Google service-account JSON key file and returns the service-account email together with the loaded RSA
    * private key.
    *
    * Raises [[com.permutive.gcp.auth.errors.UnableToGetClientData UnableToGetClientData]] when the file cannot be read,
    * the JSON does not parse, the `client_email`/`private_key` fields are missing, or the PEM-encoded key fails to
    * decode.
    */
  final def googleServiceAccount[F[_]: Files: Concurrent](path: Path): F[ServiceAccount] =
    Files[F]
      .readUtf8(path)
      .compile
      .string
      .flatMap(parser.decode[ServiceAccount](_).liftTo[F])
      .adaptError { case t => new UnableToGetClientData(path, t) }

  /** Resolves [[defaultCredentialsFilePath]] and, if the file exists, reads and parses it into a [[CredentialsFile]].
    *
    *   - `None` — no file at the resolved path.
    *   - `Some(ServiceAccount | AuthorizedUser)` — file exists and parses into one of the supported AST cases.
    *
    * Raises [[com.permutive.gcp.auth.errors.UnableToGetDefaultCredentials UnableToGetDefaultCredentials]] when JSON
    * parse, required-field extraction, private-key decoding, or the `type` field rejects a non-supported value (in the
    * last case, the underlying `DecodingFailure` is in the cause chain with message "Unsupported credentials file type:
    * ...").
    */
  final def defaultCredentialsFile[F[_]: Sync: Files]: F[(Path, Option[CredentialsFile])] =
    Sync[F]
      .delay(defaultCredentialsFilePath)
      .mproduct(Files[F].exists(_))
      .flatMap {
        case (path, true) =>
          Files[F]
            .readUtf8(path)
            .compile
            .string
            .flatMap(parser.decode[CredentialsFile](_).liftTo[F].map(path -> _.some))
            .adaptError { case t => new UnableToGetDefaultCredentials(path, t) }

        case (path, false) =>
          (path, Option.empty[CredentialsFile]).pure[F]
      }

  /** Location the ADC file is expected at. Honours `GOOGLE_APPLICATION_CREDENTIALS` when set, otherwise falls back to
    * `%AppData%/gcloud/application_default_credentials.json` on Windows or
    * `~/.config/gcloud/application_default_credentials.json` everywhere else (created by
    * `gcloud auth application-default login`).
    */
  private def defaultCredentialsFilePath: Path = sys.env.get("GOOGLE_APPLICATION_CREDENTIALS").map(Path(_)).getOrElse {
    val os = sys.props.getOrElse("os.name", "").toLowerCase()

    if (os.indexOf("windows") >= 0)
      Path(sys.env("APPDATA")) / "gcloud" / "application_default_credentials.json"
    else
      Path(sys.props.getOrElse("user.home", "")) / ".config" / "gcloud" / "application_default_credentials.json"
  }

}
