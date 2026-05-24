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
      assertEquals(result.clientEmail, ClientEmail("my@example.com"))
      assertEquals(result.privateKey.getAlgorithm(), "RSA")
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

  ////////////////////////////////////
  // Parser.defaultCredentialsFile  //
  ////////////////////////////////////

  def fixture(resource: String) = ResourceFunFixture {
    Resource.make {
      IO(sys.props("user.home")).flatTap(_ => IO(sys.props.put("user.home", getClass.getResource(resource).getPath())))
    }(userHome => IO(sys.props.put("user.home", userHome)).void)
  }

  fixture("/default/valid").test("Parser.defaultCredentialsFile parses an authorized_user file") { _ =>
    val expected = Parser.CredentialsFile.AuthorizedUser(
      ClientId("my-client-id"),
      ClientSecret("my-client-secret"),
      RefreshToken("refresh_token")
    )

    assertIO(Parser.defaultCredentialsFile[IO].map(_._2), Some(expected))
  }

  fixture("/default/sa-valid").test("Parser.defaultCredentialsFile parses a service_account file") { _ =>
    Parser.defaultCredentialsFile[IO].map {
      case (_, Some(Parser.CredentialsFile.ServiceAccount(email, key))) =>
        assertEquals(email, ClientEmail("my@example.com"))
        assertEquals(key.getAlgorithm(), "RSA")
      case other =>
        fail(s"expected Some(ServiceAccount), got: $other")
    }
  }

  fixture("/").test("Parser.defaultCredentialsFile returns None when no file is present") { _ =>
    assertIO(Parser.defaultCredentialsFile[IO].map(_._2), None)
  }

  fixture("/default/external")
    .test("Parser.defaultCredentialsFile raises UnableToGetDefaultCredentials for an external_account file") { _ =>
      val path            = resourcePath("default/external/.config/gcloud/application_default_credentials.json")
      val expectedMessage = s"Attempted to parse default credentials from `$path` ended in failure"

      interceptMessageIO[UnableToGetDefaultCredentials](expectedMessage) {
        Parser.defaultCredentialsFile[IO]
      }
    }

  fixture("/default/empty").test("Parser.defaultCredentialsFile raises UnableToGetDefaultCredentials on empty file") {
    _ =>
      val path            = resourcePath("default/empty/.config/gcloud/application_default_credentials.json")
      val expectedMessage = s"Attempted to parse default credentials from `$path` ended in failure"

      interceptMessageIO[UnableToGetDefaultCredentials](expectedMessage) {
        Parser.defaultCredentialsFile[IO]
      }
  }

  fixture("/default/invalid").test(
    "Parser.defaultCredentialsFile raises UnableToGetDefaultCredentials on invalid file"
  ) { _ =>
    val path            = resourcePath("default/invalid/.config/gcloud/application_default_credentials.json")
    val expectedMessage = s"Attempted to parse default credentials from `$path` ended in failure"

    interceptMessageIO[UnableToGetDefaultCredentials](expectedMessage) {
      Parser.defaultCredentialsFile[IO]
    }
  }

  private def resourcePath(file: String) = Path(getClass.getResource("/").getPath()) / file

}
