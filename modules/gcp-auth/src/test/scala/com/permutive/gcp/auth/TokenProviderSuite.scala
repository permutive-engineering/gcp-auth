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

package com.permutive.gcp.auth

import java.security.KeyPairGenerator
import java.security.interfaces.RSAPrivateKey
import java.time.Instant
import java.util.concurrent.atomic.AtomicInteger

import cats.effect.IO
import cats.effect.Resource
import cats.syntax.all._

import com.permutive.gcp.auth.errors.DefaultCredentialsFileNotFound
import com.permutive.gcp.auth.errors.UnableToGetClientData
import com.permutive.gcp.auth.errors.UnableToGetDefaultCredentials
import com.permutive.gcp.auth.errors.UnableToGetToken
import com.permutive.gcp.auth.errors.UnsupportedCredentialsType
import com.permutive.gcp.auth.models.AccessToken
import com.permutive.gcp.auth.models.ClientEmail
import com.permutive.gcp.auth.models.ClientId
import com.permutive.gcp.auth.models.ClientSecret
import com.permutive.gcp.auth.models.ExpiresIn
import com.permutive.gcp.auth.models.RefreshToken
import com.permutive.gcp.auth.models.Token
import fs2.Stream
import io.circe.Json
import io.circe.syntax._
import munit.CatsEffectSuite
import munit.Http4sMUnitSyntax
import org.http4s.HttpApp
import org.http4s.Request
import org.http4s.circe._
import org.http4s.client.Client
import org.typelevel.ci._
import pdi.jwt.JwtCirce
import pdi.jwt.JwtClaim

class TokenProviderSuite extends CatsEffectSuite with Http4sMUnitSyntax {

  /////////////////////////
  // TokenProvider.const //
  /////////////////////////

  test("TokenProvider.const returns always the same access-token") {
    val tokenProvider = TokenProvider.const[IO](AccessToken.noop)

    val tokens = Stream.repeatEval(tokenProvider.accessToken).take(10).compile.toList

    val expected = List.fill(10)(AccessToken.noop)

    assertIO(tokens, expected)
  }

  ////////////////////////////
  // TokenProvider.identity //
  ////////////////////////////

  test("TokenProvider.identity retrieves and calculates expiration") {
    val audience = uri"http://example.com/my-audience"

    val expiration = Instant.now().plusSeconds(60).getEpochSecond()

    val client = Client.from {
      case req @ GET -> Root / "computeMetadata" / "v1" / "instance" / "service-accounts" / "default" / "identity"
          if req.hasParam("audience", audience.renderString) && req.hasHeader("Metadata-Flavor", "Google") =>
        Ok(JwtCirce.encode(JwtClaim(expiration = expiration.some)))
    }

    for {
      tokenProvider <- TokenProvider.identity[IO](client, audience)
      token         <- tokenProvider.accessToken
    } yield {
      assert(token.token.value.nonEmpty)
      assert(token.expiresIn.value <= 60)
    }
  }

  test("TokenProvider.identity returns an error if expiration is not found") {
    val audience = uri"http://example.com/my-audience"

    val client = Client.from {
      case req @ GET -> Root / "computeMetadata" / "v1" / "instance" / "service-accounts" / "default" / "identity"
          if req.hasParam("audience", audience.renderString) && req.hasHeader("Metadata-Flavor", "Google") =>
        Ok(JwtCirce.encode(JwtClaim()))
    }

    interceptIO[UnableToGetToken] {
      TokenProvider.identity[IO](client, audience).flatMap(_.accessToken)
    }
  }

  test("TokenProvider.identity returns an error on any failure") {
    val audience = uri"http://example.com/my-audience"

    val client = Client.fromHttpApp(HttpApp.notFound[IO])

    interceptIO[UnableToGetToken](TokenProvider.identity[IO](client, audience).flatMap(_.accessToken))
  }

  test("TokenProvider.identity exposes the workload's service-account email as principal") {
    val audience = uri"http://example.com/my-audience"

    val client = Client.from {
      case req @ GET -> Root / "computeMetadata" / "v1" / "instance" / "service-accounts" / "default" / "email"
          if req.hasHeader("Metadata-Flavor", "Google") =>
        Ok("workload-sa@project.iam.gserviceaccount.com")
    }

    val result = TokenProvider.identity[IO](client, audience).flatMap(_.principal)

    assertIO(result, Some("workload-sa@project.iam.gserviceaccount.com"))
  }

  ////////////////////////////
  // TokenProvider.userIdentity //
  ////////////////////////////

  fixture("/default/valid").test {
    "TokenProvider.userIdentity retrieves and calculates expiration"
  } { _ =>
    val client = Client.from { case POST -> Root / "token" =>
      Ok(Json.obj("id_token" := "token", "expires_in" := 3600))
    }

    for {
      tokenProvider <- TokenProvider.userIdentity[IO](client)
      token         <- tokenProvider.accessToken
    } yield {
      assert(token.token.value.nonEmpty)
      assertEquals(token.expiresIn.value, 3600L)
    }
  }

  fixture("/default/valid").test {
    "TokenProvider.userIdentity extracts the email claim from the id_token JWT"
  } { _ =>
    val idToken = JwtCirce.encode(JwtClaim(content = Json.obj("email" := "user@example.com").noSpaces))

    val client = Client.from { case POST -> Root / "token" =>
      Ok(Json.obj("id_token" := idToken, "expires_in" := 3600))
    }

    val result = TokenProvider.userIdentity[IO](client).flatMap(_.principal)

    assertIO(result, Some("user@example.com"))
  }

  fixture("/").test {
    "TokenProvider.userIdentity returns an error when default credentials cannot be found"
  } { _ =>
    val client = Client.fromHttpApp(HttpApp.notFound[IO])

    interceptIO[DefaultCredentialsFileNotFound.type] {
      TokenProvider.userIdentity[IO](client).flatMap(_.accessToken)
    }
  }

  //////////////////////////////////////////
  // TokenProvider.serviceAccount(Client) //
  //////////////////////////////////////////

  test("TokenProvider.serviceAccount(Client) retrieves token successfully") {
    val client = Client.from {
      case req @ GET -> Root / "computeMetadata" / "v1" / "instance" / "service-accounts" / "default" / "token"
          if req.hasHeader("Metadata-Flavor", "Google") =>
        Ok(Json.obj("access_token" := "token", "expires_in" := 3600))
    }

    val result = TokenProvider.serviceAccount[IO](client).flatMap(_.accessToken)

    assertIO(result, AccessToken(Token("token"), ExpiresIn(3600)))
  }

  test("TokenProvider.serviceAccount(Client) returns an error on any failure") {
    val client = Client.fromHttpApp(HttpApp.notFound[IO])

    interceptIO[UnableToGetToken](TokenProvider.serviceAccount[IO](client).flatMap(_.accessToken))
  }

  //////////////////////////////////////////////////////////////
  // TokenProvider.serviceAccount(Path, List[String], Client) //
  //////////////////////////////////////////////////////////////

  test("TokenProvider.serviceAccount(Path, List[String], Client) retrieves token successfully") {
    val client = Client.from { case POST -> Root / "token" =>
      Ok(Json.obj("access_token" := "token", "expires_in" := 3600))
    }

    val path = resourcePath("valid_service_account_file.json")

    val result = TokenProvider
      .serviceAccount[IO](path, "scope_1" :: "scope_2" :: Nil, client)
      .flatMap(_.accessToken)

    assertIO(result, AccessToken(Token("token"), ExpiresIn(3600)))
  }

  test("TokenProvider.serviceAccount(Path, List[String], Client) returns an error on any failure") {
    val client = Client.fromHttpApp(HttpApp.notFound[IO])

    val path = resourcePath("valid_service_account_file.json")

    interceptIO[UnableToGetToken] {
      TokenProvider
        .serviceAccount[IO](path, "scope_1" :: "scope_2" :: Nil, client)
        .flatMap(_.accessToken)
    }
  }

  test("TokenProvider.serviceAccount(Path, List[String], Client) returns an error if file is invalid") {
    val client = Client.fromHttpApp(HttpApp.notFound[IO])

    val path = resourcePath("invalid_service_account_file.json")

    interceptIO[UnableToGetClientData] {
      TokenProvider
        .serviceAccount[IO](path, "scope_1" :: "scope_2" :: Nil, client)
        .flatMap(_.accessToken)
    }
  }

  test("TokenProvider.serviceAccount(Path, List[String], Client) returns an error if file is missing") {
    val client = Client.fromHttpApp(HttpApp.notFound[IO])

    val path = resourcePath("missing_service_account_file.json")

    interceptIO[UnableToGetClientData] {
      TokenProvider
        .serviceAccount[IO](path, "scope_1" :: "scope_2" :: Nil, client)
        .flatMap(_.accessToken)
    }
  }

  ////////////////////////////////////////////////////////////////////////////////////
  // TokenProvider.serviceAccount(ClientEmail, RSAPrivateKey, List[String], Client) //
  ////////////////////////////////////////////////////////////////////////////////////

  test("TokenProvider.serviceAccount(ClientEmail, RSAPrivateKey, List[String], Client) retrieves token successfully") {
    val client = Client.from { case POST -> Root / "token" =>
      Ok(Json.obj("access_token" := "token", "expires_in" := 3600))
    }

    val key = KeyPairGenerator.getInstance("RSA").genKeyPair().getPrivate().asInstanceOf[RSAPrivateKey]

    val tokenProvider =
      TokenProvider.serviceAccount[IO](ClientEmail("something"), key, "scope_1" :: "scope_2" :: Nil, client)

    val result = tokenProvider.accessToken

    assertIO(result, AccessToken(Token("token"), ExpiresIn(3600)))
  }

  test {
    "TokenProvider.serviceAccount(ClientEmail, RSAPrivateKey, List[String], Client) returns an error on any failure"
  } {
    val client = Client.fromHttpApp(HttpApp.notFound[IO])

    val key = KeyPairGenerator.getInstance("RSA").genKeyPair().getPrivate().asInstanceOf[RSAPrivateKey]

    val tokenProvider =
      TokenProvider.serviceAccount[IO](ClientEmail("something"), key, "scope_1" :: "scope_2" :: Nil, client)

    interceptIO[UnableToGetToken](tokenProvider.accessToken)
  }

  ///////////////////////////////////////
  // TokenProvider.userAccount(Client) //
  ///////////////////////////////////////

  fixture("/default/valid").test {
    "TokenProvider.userAccount(Client) retrieves token successfully"
  } { _ =>
    val client = Client.from { case POST -> Root / "token" =>
      Ok(Json.obj("access_token" := "token", "expires_in" := 3600))
    }

    val result = TokenProvider
      .userAccount[IO](client)
      .flatMap(_.accessToken)

    assertIO(result, AccessToken(Token("token"), ExpiresIn(3600)))
  }

  fixture("/").test {
    "TokenProvider.userAccount(Client) retuns an error on any failure"
  } { _ =>
    val client = Client.from { case POST -> Root / "token" =>
      Ok(Json.obj("access_token" := "token", "expires_in" := 3600))
    }

    interceptIO[DefaultCredentialsFileNotFound.type] {
      TokenProvider
        .userAccount[IO](client)
        .flatMap(_.accessToken)
    }
  }

  /////////////////////////////////////////////////////////////////////////////
  // TokenProvider.userAccount(ClientId, ClientSecret, RefreshToken, Client) //
  /////////////////////////////////////////////////////////////////////////////

  test("TokenProvider.userAccount(ClientId, ClientSecret, RefreshToken, Client) retrieves token successfully") {
    val client = Client.from { case POST -> Root / "token" =>
      Ok(Json.obj("access_token" := "token", "expires_in" := 3600))
    }

    val result = TokenProvider
      .userAccount[IO](ClientId("client_id"), ClientSecret("client_secret"), RefreshToken("refresh_token"), client)
      .flatMap(_.accessToken)

    assertIO(result, AccessToken(Token("token"), ExpiresIn(3600)))
  }

  test("TokenProvider.userAccount(ClientId, ClientSecret, RefreshToken, Client) retuns an error on any failure") {
    val client = Client.fromHttpApp(HttpApp.notFound[IO])

    interceptIO[UnableToGetToken] {
      TokenProvider
        .userAccount[IO](ClientId("client_id"), ClientSecret("client_secret"), RefreshToken("refresh_token"), client)
        .flatMap(_.accessToken)
    }
  }

  ///////////////////////////////////////////////////
  // TokenProvider.userAccount(Path, Path, Client) //
  ///////////////////////////////////////////////////

  test("TokenProvider.userAccount(Path, Path, Client) retrieves token successfully") {
    val client = Client.from { case POST -> Root / "token" =>
      Ok(Json.obj("access_token" := "token", "expires_in" := 3600))
    }

    val clientSecretsPath = resourcePath("valid_client_secrets_file.json")
    val refreshTokenPath  = resourcePath("standard_refresh_token_file.txt")

    val result = TokenProvider
      .userAccount[IO](clientSecretsPath, refreshTokenPath, client)
      .flatMap(_.accessToken)

    assertIO(result, AccessToken(Token("token"), ExpiresIn(3600)))
  }

  test("TokenProvider.userAccount(Path, Path, Client) retuns an error on any failure") {
    val client = Client.fromHttpApp(HttpApp.notFound[IO])

    val clientSecretsPath = resourcePath("valid_client_secrets_file.json")
    val refreshTokenPath  = resourcePath("standard_refresh_token_file.txt")

    interceptIO[UnableToGetToken] {
      TokenProvider
        .userAccount[IO](clientSecretsPath, refreshTokenPath, client)
        .flatMap(_.accessToken)
    }
  }

  //////////////////////////////
  // TokenProvider.principal //
  //////////////////////////////

  test("TokenProvider.principal returns None for const") {
    val tokenProvider = TokenProvider.const[IO](AccessToken.noop)

    assertIO(tokenProvider.principal, None)
  }

  test("TokenProvider.principal for serviceAccount(client) reads metadata /email") {
    val client = Client.from {
      case req @ GET -> Root / "computeMetadata" / "v1" / "instance" / "service-accounts" / "default" / "email"
          if req.hasHeader("Metadata-Flavor", "Google") =>
        Ok("workload-sa@project.iam.gserviceaccount.com")
    }

    val result = TokenProvider.serviceAccount[IO](client).flatMap(_.principal)

    assertIO(result, Some("workload-sa@project.iam.gserviceaccount.com"))
  }

  test("TokenProvider.principal for serviceAccount(client) propagates failure (metadata unreachable)") {
    val client = Client.fromHttpApp(HttpApp.notFound[IO])

    val result = TokenProvider.serviceAccount[IO](client).flatMap(_.principal).attempt

    result.map(r => assert(r.isLeft))
  }

  test("TokenProvider.principal for serviceAccount(Path, scopes, client) reads client_email from JSON") {
    val client = Client.fromHttpApp(HttpApp.notFound[IO])

    val path = resourcePath("valid_service_account_file.json")

    val result = TokenProvider
      .serviceAccount[IO](path, "scope" :: Nil, client)
      .flatMap(_.principal)

    assertIO(result, Some("my@example.com"))
  }

  test("TokenProvider.principal for serviceAccount(ClientEmail, key, scopes, client) returns Some(email.value)") {
    val client = Client.fromHttpApp(HttpApp.notFound[IO])

    val key = KeyPairGenerator.getInstance("RSA").genKeyPair().getPrivate().asInstanceOf[RSAPrivateKey]

    val tokenProvider =
      TokenProvider.serviceAccount[IO](ClientEmail("direct-sa@project.iam.gserviceaccount.com"), key, Nil, client)

    assertIO(tokenProvider.principal, Some("direct-sa@project.iam.gserviceaccount.com"))
  }

  test("TokenProvider.principal for userAccount(id, secret, refresh, client) reads userinfo") {
    val client = Client.from {
      case POST -> Root / "token" =>
        Ok(Json.obj("access_token" := "abc", "expires_in" := 3600))
      case req @ GET -> Root / "oauth2" / "v3" / "userinfo" if req.hasHeader("Authorization", "Bearer abc") =>
        Ok(Json.obj("email" := "user@example.com"))
    }

    val result = TokenProvider
      .userAccount[IO](ClientId("client_id"), ClientSecret("client_secret"), RefreshToken("refresh_token"), client)
      .flatMap(_.principal)

    assertIO(result, Some("user@example.com"))
  }

  test("TokenProvider.principal for userAccount(...) returns None on failure") {
    val client = Client.fromHttpApp(HttpApp.notFound[IO])

    val result = TokenProvider
      .userAccount[IO](ClientId("client_id"), ClientSecret("client_secret"), RefreshToken("refresh_token"), client)
      .flatMap(_.principal)

    assertIO(result, None)
  }

  ////////////////////////////////////
  // TokenProvider.auto             //
  ////////////////////////////////////

  fixture("/default/valid").test("TokenProvider.auto routes to userAccount when ADC user file exists") { _ =>
    val client = Client.from {
      case POST -> Root / "token" =>
        Ok(Json.obj("access_token" := "user-token", "expires_in" := 3600))
      case req @ GET -> Root / "oauth2" / "v3" / "userinfo" if req.hasHeader("Authorization", "Bearer user-token") =>
        Ok(Json.obj("email" := "adc-user@example.com"))
    }

    val result = TokenProvider.auto[IO](client).flatMap { provider =>
      (provider.accessToken, provider.principal).tupled
    }

    assertIO(result, (AccessToken(Token("user-token"), ExpiresIn(3600)), Some("adc-user@example.com")))
  }

  fixture("/default/sa-valid").test("TokenProvider.auto routes to serviceAccount when ADC SA file exists") { _ =>
    val client = Client.from { case POST -> Root / "token" =>
      Ok(Json.obj("access_token" := "sa-token", "expires_in" := 3600))
    }

    val result = TokenProvider.auto[IO](client).flatMap { provider =>
      (provider.accessToken, provider.principal).tupled
    }

    assertIO(result, (AccessToken(Token("sa-token"), ExpiresIn(3600)), Some("my@example.com")))
  }

  fixture("/default/missing").test("TokenProvider.auto falls back to metadata server when no ADC file is found") { _ =>
    val client = Client.from {
      case req @ GET -> Root / "computeMetadata" / "v1" / "instance" / "service-accounts" / "default" / "token"
          if req.hasHeader("Metadata-Flavor", "Google") =>
        Ok(Json.obj("access_token" := "metadata-token", "expires_in" := 3600))
      case req @ GET -> Root / "computeMetadata" / "v1" / "instance" / "service-accounts" / "default" / "email"
          if req.hasHeader("Metadata-Flavor", "Google") =>
        Ok("metadata-sa@project.iam.gserviceaccount.com")
    }

    val result = TokenProvider.auto[IO](client).flatMap { provider =>
      (provider.accessToken, provider.principal).tupled
    }

    assertIO(
      result,
      (AccessToken(Token("metadata-token"), ExpiresIn(3600)), Some("metadata-sa@project.iam.gserviceaccount.com"))
    )
  }

  ///////////////////////////////////////////////
  // TokenProvider.auto (identity-token flavor) //
  ///////////////////////////////////////////////

  fixture("/default/valid").test("TokenProvider.auto(client, audience) routes to userIdentity when ADC file exists") {
    _ =>
      val idToken = JwtCirce.encode(JwtClaim(content = Json.obj("email" := "adc-user@example.com").noSpaces))

      val client = Client.from { case POST -> Root / "token" =>
        Ok(Json.obj("id_token" := idToken, "expires_in" := 3600))
      }

      val audience = uri"http://example.com/my-audience"

      val result = TokenProvider.auto[IO](client, audience).flatMap(_.principal)

      assertIO(result, Some("adc-user@example.com"))
  }

  fixture("/default/missing")
    .test("TokenProvider.auto(client, audience) falls back to metadata server when no ADC file is found") { _ =>
      val audience = uri"http://example.com/my-audience"

      val expiration = Instant.now().plusSeconds(60).getEpochSecond()

      val client = Client.from {
        case req @ GET -> Root / "computeMetadata" / "v1" / "instance" / "service-accounts" / "default" / "identity"
            if req.hasParam("audience", audience.renderString) && req.hasHeader("Metadata-Flavor", "Google") =>
          Ok(JwtCirce.encode(JwtClaim(expiration = expiration.some)))
        case req @ GET -> Root / "computeMetadata" / "v1" / "instance" / "service-accounts" / "default" / "email"
            if req.hasHeader("Metadata-Flavor", "Google") =>
          Ok("metadata-sa@project.iam.gserviceaccount.com")
      }

      val result = TokenProvider.auto[IO](client, audience).flatMap(_.principal)

      assertIO(result, Some("metadata-sa@project.iam.gserviceaccount.com"))
    }

  fixture("/default/external")
    .test("TokenProvider.auto raises UnableToGetDefaultCredentials for non-SA / non-user types") { _ =>
      val client = Client.from(PartialFunction.empty)

      val result = TokenProvider.auto[IO](client).flatMap(_.accessToken).attempt

      result.map {
        case Left(_: UnableToGetDefaultCredentials) => ()
        case other                                  => fail(s"expected UnableToGetDefaultCredentials, got: $other")
      }
    }

  fixture("/default/sa-valid")
    .test("TokenProvider.auto(client, audience) raises UnsupportedCredentialsType for service_account") { _ =>
      val audience = uri"http://example.com/my-audience"
      val client   = Client.from(PartialFunction.empty)

      val result = TokenProvider.auto[IO](client, audience).flatMap(_.accessToken).attempt

      result.map {
        case Left(_: UnsupportedCredentialsType) => ()
        case other                               => fail(s"expected UnsupportedCredentialsType, got: $other")
      }
    }

  fixture("/default/missing").test("TokenProvider.auto memoises principal across calls") { _ =>
    val counter = new AtomicInteger(0)

    val client = Client.from {
      case req @ GET -> Root / "computeMetadata" / "v1" / "instance" / "service-accounts" / "default" / "token"
          if req.hasHeader("Metadata-Flavor", "Google") =>
        Ok(Json.obj("access_token" := "tok", "expires_in" := 3600))
      case req @ GET -> Root / "computeMetadata" / "v1" / "instance" / "service-accounts" / "default" / "email"
          if req.hasHeader("Metadata-Flavor", "Google") =>
        IO(counter.incrementAndGet()) *> Ok("metadata-sa@project.iam.gserviceaccount.com")
    }

    val result = TokenProvider.auto[IO](client).flatMap { provider =>
      provider.principal.replicateA(5).map(_ => counter.get())
    }

    assertIO(result, 1)
  }

  /////////////////////////////////////////
  // TokenProvider.cached preserves principal
  /////////////////////////////////////////

  test("TokenProvider.cached preserves principal from the underlying provider") {
    val client = Client.from {
      case req @ GET -> Root / "computeMetadata" / "v1" / "instance" / "service-accounts" / "default" / "token"
          if req.hasHeader("Metadata-Flavor", "Google") =>
        Ok(Json.obj("access_token" := "tok", "expires_in" := 3600))
      case req @ GET -> Root / "computeMetadata" / "v1" / "instance" / "service-accounts" / "default" / "email"
          if req.hasHeader("Metadata-Flavor", "Google") =>
        Ok("workload-sa@project.iam.gserviceaccount.com")
    }

    val result = TokenProvider.cached[IO].build(TokenProvider.serviceAccount[IO](client)).use(_.principal)

    assertIO(result, Some("workload-sa@project.iam.gserviceaccount.com"))
  }

  test("TokenProvider.cached memoises principal across calls") {
    val counter = new AtomicInteger(0)

    val client = Client.from {
      case req @ GET -> Root / "computeMetadata" / "v1" / "instance" / "service-accounts" / "default" / "token"
          if req.hasHeader("Metadata-Flavor", "Google") =>
        Ok(Json.obj("access_token" := "tok", "expires_in" := 3600))
      case req @ GET -> Root / "computeMetadata" / "v1" / "instance" / "service-accounts" / "default" / "email"
          if req.hasHeader("Metadata-Flavor", "Google") =>
        IO(counter.incrementAndGet()) *> Ok("workload-sa@project.iam.gserviceaccount.com")
    }

    val result = TokenProvider.cached[IO].build(TokenProvider.serviceAccount[IO](client)).use { cached =>
      cached.principal.replicateA(5).map(_ => counter.get())
    }

    assertIO(result, 1)
  }

  ////////////////////////////////////
  // TokenProvider.clientMiddleware //
  ////////////////////////////////////

  test("TokenProvider.clientMiddleware successfully wraps a Client") {
    val client = Client.from {
      case req @ GET -> Root / "hello" if req.hasHeader("Authorization", "Bearer noop") =>
        Ok("Success!")
    }

    val authedClient = TokenProvider
      .const[IO](AccessToken.noop)
      .clientMiddleware(client)

    val result = authedClient.expect[String]("hello")

    assertIO(result, "Success!")
  }

  //////////////
  // Fixtures //
  //////////////

  def fixture(resource: String) = ResourceFunFixture {
    Resource.make {
      IO(sys.props("user.home")).flatTap(_ => IO(sys.props.put("user.home", getClass.getResource(resource).getPath())))
    }(userHome => IO(sys.props.put("user.home", userHome)).void)
  }

  private def resourcePath(file: String) = fs2.io.file.Path(getClass.getResource("/").getPath()) / file

  implicit private class RequestTestOps(request: Request[IO]) {

    def hasParam(name: String, value: String) =
      request.params.get(name).contains(value)

    def hasHeader(name: String, value: String) =
      request.headers.get(ci"$name").map(_.map(_.value).toList).contains(value :: Nil)

  }

}
