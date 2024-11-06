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

package com.permutive.gcp.auth.pureconfig

import cats.effect.IO
import cats.effect.Resource

import com.permutive.gcp.auth.models.AccessToken
import com.permutive.gcp.auth.models.ExpiresIn
import com.permutive.gcp.auth.models.Token
import io.circe.Json
import io.circe.syntax._
import munit.CatsEffectSuite
import munit.Http4sMUnitSyntax
import org.http4s.HttpApp
import org.http4s.circe._
import org.http4s.client.Client
import pureconfig.ConfigReader
import pureconfig.ConfigSource

class TypeTokenSuite extends CatsEffectSuite with Http4sMUnitSyntax {

  fixture("/").test {
    "TokenType.UserAccount can be loaded from configuration"
  } { _ =>
    val client = Client.from { case POST -> Root / "token" =>
      Ok(Json.obj("access_token" := "token", "expires_in" := 3600))
    }

    val config = ConfigSource.string("""token-type = "user-account"""").loadOrThrow[Config]

    assertEquals(config.tokenType, TokenType.UserAccount)

    val result = config.tokenType
      .tokenProvider(client)
      .flatMap(_.accessToken)

    assertIO(result, AccessToken(Token("token"), ExpiresIn(3600)))
  }

  test("TokenType.ServiceAccount can be loaded from configuration") {
    val client = Client.from {
      case GET -> Root / "computeMetadata" / "v1" / "instance" / "service-accounts" / "default" / "token" =>
        Ok(Json.obj("access_token" := "token", "expires_in" := 3600))
    }

    val config = ConfigSource.string("""token-type = "service-account"""").loadOrThrow[Config]

    assertEquals(config.tokenType, TokenType.ServiceAccount)

    val result = config.tokenType
      .tokenProvider(client)
      .flatMap(_.accessToken)

    assertIO(result, AccessToken(Token("token"), ExpiresIn(3600)))
  }

  test("TokenType.NoOp can be loaded from configuration") {
    val client = Client.fromHttpApp(HttpApp.notFound[IO])

    val config = ConfigSource.string("""token-type = "no-op"""").loadOrThrow[Config]

    assertEquals(config.tokenType, TokenType.NoOp)

    val result = config.tokenType
      .tokenProvider(client)
      .flatMap(_.accessToken)

    assertIO(result, AccessToken.noop)
  }

  def fixture(resource: String) = ResourceFunFixture {
    Resource.make {
      IO(sys.props("user.home")).flatTap(_ => IO(sys.props.put("user.home", getClass.getResource(resource).getPath())))
    }(userHome => IO(sys.props.put("user.home", userHome)).void)
  }

}

final case class Config(tokenType: TokenType)

object Config {

  implicit val ConfigConfigReader: ConfigReader[Config] = ConfigReader.forProduct1("token-type")(Config.apply)

}
