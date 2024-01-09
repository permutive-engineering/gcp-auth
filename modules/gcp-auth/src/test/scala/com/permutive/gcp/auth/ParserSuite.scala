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

import scala.util.chaining._

import cats.effect.IO
import cats.effect.kernel.Resource

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
import munit.CatsEffectSuite

class ParserSuite extends CatsEffectSuite {

  ///////////////////////////////
  // Parser.googleRefreshToken //
  ///////////////////////////////

  test("Parser.googleRefreshToken should parse a valid file") {
    val path = resourcePath("standard_refresh_token_file.txt")

    val result = Parser.googleRefreshToken[IO](path)

    val expected = RefreshToken("refresh-token")

    assertIO(result, expected)
  }

  test("Parser.googleRefreshToken should only include the first line of a file, ignoring others") {
    val path = resourcePath("multi_line_refresh_token_file.txt")

    for {
      parsed  <- Parser.googleRefreshToken[IO](path)
      content <- Files[IO].readUtf8Lines(path).compile.toList
    } yield {
      val expected = RefreshToken("refresh-token")

      assertEquals(parsed, expected)
      assert(content.size > 1)
    }
  }

  test("Parser.googleRefreshToken should raise a failure if the file is empty") {
    val path = resourcePath("empty_refresh_token_file.txt")

    val expectedMessage = s"Attempted to parse a Google refresh token but the file was empty: $path"

    interceptMessageIO[EmptyRefreshTokenFile](expectedMessage) {
      Parser.googleRefreshToken[IO](path)
    }
  }

  ////////////////////////////////
  // Parser.googleClientSecrets //
  ////////////////////////////////

  test("Parser.googleClientSecrets should parse a valid file") {
    val path = resourcePath("valid_client_secrets_file.json")

    val result = Parser.googleClientSecrets[IO](path)

    val expected = (
      ClientId("my-client-id"),
      ClientSecret("my-client-secret")
    )

    assertIO(result, expected)
  }

  test("Parser.googleClientSecrets should raise a failure if the file is missing") {
    val path = resourcePath("missing_client_secrets_file.json")

    val expectedMessage = s"Attempted to parse client secrets from `$path` ended in failure"

    interceptMessageIO[UnableToGetClientSecrets](expectedMessage) {
      Parser.googleClientSecrets[IO](path)
    }
  }

  test("Parser.googleClientSecrets should raise a failure if the file is empty") {
    val path = resourcePath("empty_client_secrets_file.json")

    val expectedMessage = s"Attempted to parse client secrets from `$path` ended in failure"

    interceptMessageIO[UnableToGetClientSecrets](expectedMessage) {
      Parser.googleClientSecrets[IO](path)
    }
  }

  test("Parser.googleClientSecrets should raise a failure if the file is invalid") {
    val path = resourcePath("invalid_client_secrets_file.json")

    val expectedMessage = s"Attempted to parse client secrets from `$path` ended in failure"

    interceptMessageIO[UnableToGetClientSecrets](expectedMessage) {
      Parser.googleClientSecrets[IO](path)
    }
  }

  /////////////////////////////////
  // Parser.googleServiceAccount //
  /////////////////////////////////

  test("Parser.googleServiceAccount should parse a valid file") {
    val path = resourcePath("valid_service_account_file.json")

    for {
      result <- Parser.googleServiceAccount[IO](path)
    } yield {
      val (email, rsa) = result

      val expected = ClientEmail("my@example.com")

      assertEquals(email, expected)
      assertEquals(rsa.getAlgorithm(), "RSA")
    }
  }

  test("Parser.googleServiceAccount should raise a failure if the file is missing") {
    val path = resourcePath("missing_service_account_file.json")

    val expectedMessage = s"Attempted to parse client data from `$path` ended in failure"

    interceptMessageIO[UnableToGetClientData](expectedMessage) {
      Parser.googleServiceAccount[IO](path)
    }
  }

  test("Parser.googleServiceAccount should raise a failure if the file is empty") {
    val path = resourcePath("empty_service_account_file.json")

    val expectedMessage = s"Attempted to parse client data from `$path` ended in failure"

    interceptMessageIO[UnableToGetClientData](expectedMessage) {
      Parser.googleServiceAccount[IO](path)
    }
  }

  test("Parser.googleServiceAccount should raise a failure if the file is invalid") {
    val path = resourcePath("invalid_service_account_file.json")

    val expectedMessage = s"Attempted to parse client data from `$path` ended in failure"

    interceptMessageIO[UnableToGetClientData](expectedMessage) {
      Parser.googleServiceAccount[IO](path)
    }
  }

  //////////////////////////////////////////
  // Parser.applicationDefaultCredentials //
  //////////////////////////////////////////

  def fixture(resource: String) = Resource.make {
    IO(sys.props("user.home")).flatTap(_ => IO(sys.props.put("user.home", getClass.getResource(resource).getPath())))
  }(userHome => IO(sys.props.put("user.home", userHome)).void).pipe(ResourceFixture(_))

  fixture("/default/valid").test("Parser.applicationDefaultCredentials should parse a valid file") { _ =>
    val result = Parser.applicationDefaultCredentials[IO]

    val expected = (
      ClientId("my-client-id"),
      ClientSecret("my-client-secret"),
      RefreshToken("refresh_token")
    )

    assertIO(result, expected)
  }

  fixture("/").test {
    "Parser.applicationDefaultCredentials should raise a failure if the file is missing"
  } { _ =>
    val path            = resourcePath(".config/gcloud/application_default_credentials.json")
    val expectedMessage = s"Attempted to parse default credentials from `$path` ended in failure"

    interceptMessageIO[UnableToGetDefaultCredentials](expectedMessage) {
      Parser.applicationDefaultCredentials[IO]
    }
  }

  fixture("/default/empty").test("Parser.applicationDefaultCredentials should raise a failure if the file is empty") {
    _ =>
      val path            = resourcePath("default/empty/.config/gcloud/application_default_credentials.json")
      val expectedMessage = s"Attempted to parse default credentials from `$path` ended in failure"

      interceptMessageIO[UnableToGetDefaultCredentials](expectedMessage) {
        Parser.applicationDefaultCredentials[IO]
      }
  }

  fixture("/default/invalid").test(
    "Parser.applicationDefaultCredentials should raise a failure if the file is invalid"
  ) { _ =>
    val path = resourcePath("default/invalid/.config/gcloud/application_default_credentials.json")

    val expectedMessage = s"Attempted to parse default credentials from `$path` ended in failure"

    interceptMessageIO[UnableToGetDefaultCredentials](expectedMessage) {
      Parser.applicationDefaultCredentials[IO]
    }
  }

  private def resourcePath(file: String) = Path(getClass.getResource("/").getPath()) / file

}
