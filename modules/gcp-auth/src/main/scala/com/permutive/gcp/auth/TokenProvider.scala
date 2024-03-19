/*
 * Copyright 2024 Permutive Ltd. <https://permutive.com>
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

import java.security.interfaces.RSAPrivateKey
import java.time.Duration
import java.time.Instant
import java.util.Date

import scala.concurrent.duration._

import cats.Applicative
import cats.effect.Async
import cats.effect.Clock
import cats.effect.Concurrent
import cats.effect.MonadCancelThrow
import cats.effect.Resource
import cats.effect.Temporal
import cats.effect.syntax.all._
import cats.syntax.all._

import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm
import com.permutive.gcp.auth.errors.ExpirationNotFound
import com.permutive.gcp.auth.errors.UnableToGetToken
import com.permutive.gcp.auth.models.AccessToken
import com.permutive.gcp.auth.models.ClientEmail
import com.permutive.gcp.auth.models.ClientId
import com.permutive.gcp.auth.models.ClientSecret
import com.permutive.gcp.auth.models.ExpiresIn
import com.permutive.gcp.auth.models.RefreshToken
import com.permutive.gcp.auth.models.Token
import com.permutive.refreshable.Refreshable
import fs2.io.file.Files
import fs2.io.file.Path
import org.http4s.Header
import org.http4s.Method.GET
import org.http4s.Method.POST
import org.http4s.Request
import org.http4s.Uri
import org.http4s.UrlForm
import org.http4s.client.Client
import org.http4s.syntax.all._
import org.typelevel.ci._
import pdi.jwt.JwtCirce
import pdi.jwt.JwtOptions
import retry.RetryDetails
import retry.RetryPolicy

/** Represents a class that is able to retrieve a specific type of access token from Google's oauth APIs. */
trait TokenProvider[F[_]] {

  /** Retrieve a valid access token. */
  def accessToken: F[AccessToken]

  /** Wraps a [[org.http4s.client.Client Client]] ensuring every request coming out from this client contain an
    * `Authorization` header with an [[com.permutive.gcp.auth.models.AccessToken AccessToken]].
    */
  def clientMiddleware(client: Client[F])(implicit F: MonadCancelThrow[F]): Client[F] = Client[F] { request =>
    accessToken
      .map(_.asHeader)
      .map(request.putHeaders(_))
      .toResource
      .flatMap(client.run)
  }

}

object TokenProvider {

  def apply[F[_]](implicit ev: TokenProvider[F]): TokenProvider[F] = ev

  def create[F[_]](fa: F[AccessToken]): TokenProvider[F] = new TokenProvider[F] {

    override def accessToken: F[AccessToken] = fa

  }

  /** Suitable safety period for an token from the instance metadata.
    *
    * The GCP metadata endpoint caches tokens for 5 minutes until their expiry. The value here (4 minutes) should ensure
    * a new token will be provided and have no risk of requests using an expired token.
    *
    * @see
    *   https://cloud.google.com/compute/docs/access/create-enable-service-accounts-for-instances#applications
    */
  val InstanceMetadataOAuthSafetyPeriod: FiniteDuration = 4.minutes

  /** Transforms a `TokenProvider` in a cached version of itself that automatically refreshes the token given its
    * expiration.
    */
  def cached[F[_]: Temporal]: CachedBuilder[F] =
    new CachedBuilder[F](tokenProvider => Refreshable.builder(tokenProvider.accessToken))
      .safetyPeriod(InstanceMetadataOAuthSafetyPeriod)

  final class CachedBuilder[F[_]] private[auth] (
      private val builder: TokenProvider[F] => Refreshable.RefreshableBuilder[F, AccessToken]
  ) {

    /** How much time less than the indicated expiry to cache a token for; this is to give a safety buffer to ensure an
      * expired token is never used in a request. Defaults to four minutes to ensure a new token will be provided and
      * have no risk of requests using an expired token
      */
    def safetyPeriod(duration: FiniteDuration): CachedBuilder[F] =
      new CachedBuilder(builder.map(_.cacheDuration(_.expiresIn.value.seconds - duration)))

    /** What to do if retrying to refresh the token fails. The refresh fiber will have failed at this point and the
      * token will grow stale. It is up to the user to handle this failure, as they see fit, in their application
      */
    def onRefreshFailure(callback: PartialFunction[(Throwable, RetryDetails), F[Unit]]): CachedBuilder[F] =
      new CachedBuilder(builder.map(_.onRefreshFailure(callback)))

    /** What to do if retrying to refresh the token fails even after retries. The refresh fiber will have failed at this
      * point and the value will grow stale. It is up to the user to handle this failure, as they see fit, in their
      * application
      */
    def onExhaustedRetries(callback: PartialFunction[Throwable, F[Unit]]): CachedBuilder[F] =
      new CachedBuilder(builder.map(_.onExhaustedRetries(callback)))

    /** A callback invoked whenever a new token is generated, the [[scala.concurrent.duration.FiniteDuration]] is the
      * period that will be waited before the next new token
      */
    def onNewToken(callback: (AccessToken, FiniteDuration) => F[Unit]): CachedBuilder[F] =
      new CachedBuilder(builder.map(_.onNewValue(callback)))

    /** An optional configuration object for attempting to retry retrieving the token on failure. When no value is
      * supplied this defaults to 5 retries with a delay between each of 200 milliseconds.
      */
    def retryPolicy(retryPolicy: RetryPolicy[F]): CachedBuilder[F] =
      new CachedBuilder(builder.map(_.retryPolicy(retryPolicy)))

    def build(tokenProvider: TokenProvider[F]): Resource[F, TokenProvider[F]] =
      builder(tokenProvider).resource.map(builder => TokenProvider.create(builder.value))

    def build(tokenProvider: F[TokenProvider[F]]): Resource[F, TokenProvider[F]] =
      tokenProvider.toResource.flatMap(build)

  }

  /** Retrieves an identity token using Google's metadata server for a specific audience.
    *
    * Identity tokens can be used for calling Cloud Run services.
    *
    * '''Important!''' This method can only be run from within a workload container in GCP. The call will fail
    * otherwise.
    *
    * @see
    *   https://cloud.google.com/run/docs/securing/service-identity#fetching_identity_and_access_tokens_using_the_metadata_server
    */
  def identity[F[_]: Concurrent: Clock](httpClient: Client[F], audience: Uri): TokenProvider[F] =
    TokenProvider.create {
      val uri = uri"http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity" +?
        ("audience" -> audience)

      val request = Request[F](GET, uri).putHeaders(Header.Raw(ci"Metadata-Flavor", "Google"))

      val jwtOptions = JwtOptions(signature = false)

      httpClient
        .expect[String](request)
        .mproduct(JwtCirce.decode(_, jwtOptions).toEither.flatMap(_.expiration.toRight(ExpirationNotFound)).liftTo[F])
        .flatMap { case (token, expiration) =>
          Clock[F].realTimeInstant
            .map(now => Duration.between(now, Instant.ofEpochSecond(expiration)).toSeconds())
            .map(ExpiresIn(_))
            .map(AccessToken(Token(token), _))
        }
        .adaptError { case t => new UnableToGetToken(t) }
    }

  /** Retrieves a workload service account token using Google's metadata server.
    *
    * You can then user the service account token to send authenticated requests to GCP services, such as Vertex-AI,
    * Google Cloud Storage...
    *
    * '''Important!''' This method can only be run from within a workload container in GCP. The call will fail
    * otherwise.
    *
    * @see
    *   https://cloud.google.com/compute/docs/access/authenticate-workloads
    */
  def serviceAccount[F[_]: Concurrent](httpClient: Client[F]): TokenProvider[F] =
    TokenProvider.create {
      val request =
        Request[F](GET, uri"http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token")
          .putHeaders(Header.Raw(ci"Metadata-Flavor", "Google"))

      httpClient
        .expect[AccessToken](request)
        .adaptError { case t => new UnableToGetToken(t) }
    }

  /** Retrieves a service account token from Google's OAuth API.
    *
    * You can then user the service account token to send authenticated requests to GCP services, such as Vertex-AI,
    * Google Cloud Storage...
    *
    * @see
    *   https://developers.google.com/identity/protocols/oauth2
    */
  def serviceAccount[F[_]: Files: Async](
      serviceAccountPath: Path,
      scope: List[String],
      httpClient: Client[F]
  ): F[TokenProvider[F]] =
    Parser
      .googleServiceAccount(serviceAccountPath)
      .map { case (clientEmail, privateKey) => serviceAccount(clientEmail, privateKey, scope, httpClient) }

  /** Retrieves a service account token from Google's OAuth API.
    *
    * You can then user the service account token to send authenticated requests to GCP services, such as Vertex-AI,
    * Google Cloud Storage...
    *
    * @see
    *   https://developers.google.com/identity/protocols/oauth2
    */
  def serviceAccount[F[_]: Async](
      clientEmail: ClientEmail,
      privateKey: RSAPrivateKey,
      scope: List[String],
      httpClient: Client[F]
  ): TokenProvider[F] = TokenProvider.create {
    Clock[F].realTimeInstant.map { now =>
      JWT.create
        .withIssuedAt(Date.from(now))
        .withExpiresAt(Date.from(now.plusMillis(1.hour.toMillis)))
        .withAudience("https://oauth2.googleapis.com/token")
        .withClaim("scope", scope.mkString(" "))
        .withClaim("iss", clientEmail.value)
        .sign(Algorithm.RSA256(privateKey))
    }
      .map(token => UrlForm("grant_type" -> "urn:ietf:params:oauth:grant-type:jwt-bearer", "assertion" -> token))
      .map(Request[F](POST, uri"https://oauth2.googleapis.com/token").withEntity(_))
      .flatMap(httpClient.expect[AccessToken](_))
      .adaptError { case t => new UnableToGetToken(t) }
  }

  /** Retrieves a user account token from Google's OAuth API.
    *
    * You can then user the user account token to send authenticated requests to GCP services, such as Vertex-AI, Google
    * Cloud Storage...
    *
    * @see
    *   https://developers.google.com/identity/protocols/oauth2
    */
  def userAccount[F[_]: Concurrent: Files](
      clientSecretsPath: Path,
      refreshTokenPath: Path,
      httpClient: Client[F]
  ): F[TokenProvider[F]] =
    (Parser.googleClientSecrets(clientSecretsPath), Parser.googleRefreshToken(refreshTokenPath)).mapN {
      case ((clientId, clientSecret), token) =>
        userAccount(clientId, clientSecret, token, httpClient)
    }

  /** Retrieves a user account token from Google's OAuth API.
    *
    * You can then user the user account token to send authenticated requests to GCP services, such as Vertex-AI, Google
    * Cloud Storage...
    *
    * @see
    *   https://developers.google.com/identity/protocols/oauth2
    */
  def userAccount[F[_]: Concurrent](
      clientId: ClientId,
      clientSecret: ClientSecret,
      refreshToken: RefreshToken,
      httpClient: Client[F]
  ): TokenProvider[F] =
    TokenProvider.create {
      val form = UrlForm(
        "refresh_token" -> refreshToken.value,
        "client_id"     -> clientId.value,
        "client_secret" -> clientSecret.value,
        "grant_type"    -> "refresh_token"
      )

      val request = Request[F](POST, uri"https://oauth2.googleapis.com/token").withEntity(form)

      httpClient
        .expect[AccessToken](request)
        .adaptError { case t => new UnableToGetToken(t) }
    }

  /** Retrieves a user account token from Google's OAuth API using the "Application Default Credentials" file.
    *
    * By default this file is located under `~/.config/cloud/application_default_credentials.json` (or
    * `%AppData%/gcloud/application_default_credentials.json` if running on Windows) and can be created using `gcloud
    * auth application-default login` or set `GOOGLE_APPLICATION_CREDENTIALS` environment variable to override to
    * another path.
    *
    * You can then user the user account token to send authenticated requests to GCP services, such as Vertex-AI, Google
    * Cloud Storage...
    *
    * @see
    *   https://developers.google.com/identity/protocols/oauth2
    * @see
    *   https://cloud.google.com/docs/authentication/provide-credentials-adc
    */
  def userAccount[F[_]: Files: Concurrent](httpClient: Client[F]): F[TokenProvider[F]] =
    Parser.applicationDefaultCredentials.map { case (clientId, clientSecret, refreshToken) =>
      userAccount(clientId, clientSecret, refreshToken, httpClient)
    }

  def const[F[_]: Applicative](token: AccessToken): TokenProvider[F] = TokenProvider.create(token.pure)

}
