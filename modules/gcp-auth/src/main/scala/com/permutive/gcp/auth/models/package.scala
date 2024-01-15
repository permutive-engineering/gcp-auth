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

package object models {

  type Token = String with Token.Tag

  object Token extends Tagged[String] {

    def apply(value: String): Token = value.asInstanceOf[Token]

  }

  type ExpiresIn = Long with ExpiresIn.Tag

  object ExpiresIn extends Tagged[Long] {

    def apply(value: Long): ExpiresIn = value.asInstanceOf[ExpiresIn]

  }

  type ClientId = String with ClientId.Tag

  object ClientId extends Tagged[String] {

    def apply(value: String): ClientId = value.asInstanceOf[ClientId]

  }

  type ClientEmail = String with ClientEmail.Tag

  object ClientEmail extends Tagged[String] {

    def apply(value: String): ClientEmail = value.asInstanceOf[ClientEmail]

  }

  type ClientSecret = String with ClientSecret.Tag

  object ClientSecret extends Tagged[String] {

    def apply(value: String): ClientSecret = value.asInstanceOf[ClientSecret]

  }

  type RefreshToken = String with RefreshToken.Tag

  object RefreshToken extends Tagged[String] {

    def apply(value: String): RefreshToken = value.asInstanceOf[RefreshToken]

  }

}
