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

import java.security.KeyPairGenerator
import java.security.interfaces.RSAPrivateKey
import java.time.Instant

import cats.effect.IO
import cats.effect.Resource
import cats.syntax.all._

import com.permutive.gcp.auth.errors.UnableToGetClientData
import com.permutive.gcp.auth.errors.UnableToGetDefaultCredentials
import com.permutive.gcp.auth.errors.UnableToGetToken
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

    val tokenProvider = TokenProvider.identity[IO](client, audience)

    for {
      token <- tokenProvider.accessToken
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

    val tokenProvider = TokenProvider.identity[IO](client, audience)

    interceptIO[UnableToGetToken] {
      tokenProvider.accessToken
    }
  }

  test("TokenProvider.identity returns an error on any failure") {
    val audience = uri"http://example.com/my-audience"

    val client = Client.fromHttpApp(HttpApp.notFound[IO])

    val tokenProvider = TokenProvider.identity[IO](client, audience)

    interceptIO[UnableToGetToken](tokenProvider.accessToken)
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

    val tokenProvider = TokenProvider.serviceAccount[IO](client)

    val result = tokenProvider.accessToken

    assertIO(result, AccessToken(Token("token"), ExpiresIn(3600)))
  }

  test("TokenProvider.serviceAccount(Client) returns an error on any failure") {
    val client = Client.fromHttpApp(HttpApp.notFound[IO])

    val tokenProvider = TokenProvider.serviceAccount[IO](client)

    interceptIO[UnableToGetToken](tokenProvider.accessToken)
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

  def fixture(resource: String) = ResourceFunFixture {
    Resource.make {
      IO(sys.props("user.home")).flatTap(_ => IO(sys.props.put("user.home", getClass.getResource(resource).getPath())))
    }(userHome => IO(sys.props.put("user.home", userHome)).void)
  }

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

    interceptIO[UnableToGetDefaultCredentials] {
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

    val tokenProvider = TokenProvider
      .userAccount[IO](ClientId("client_id"), ClientSecret("client_secret"), RefreshToken("refresh_token"), client)

    val result = tokenProvider.accessToken

    assertIO(result, AccessToken(Token("token"), ExpiresIn(3600)))
  }

  test("TokenProvider.userAccount(ClientId, ClientSecret, RefreshToken, Client) retuns an error on any failure") {
    val client = Client.fromHttpApp(HttpApp.notFound[IO])

    val tokenProvider = TokenProvider
      .userAccount[IO](ClientId("client_id"), ClientSecret("client_secret"), RefreshToken("refresh_token"), client)

    interceptIO[UnableToGetToken](tokenProvider.accessToken)
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

  private def resourcePath(file: String) = fs2.io.file.Path(getClass.getResource("/").getPath()) / file

  implicit private class RequestTestOps(request: Request[IO]) {

    def hasParam(name: String, value: String) =
      request.params.get(name).contains(value)

    def hasHeader(name: String, value: String) =
      request.headers.get(ci"$name").map(_.map(_.value).toList).contains(value :: Nil)

  }

}
