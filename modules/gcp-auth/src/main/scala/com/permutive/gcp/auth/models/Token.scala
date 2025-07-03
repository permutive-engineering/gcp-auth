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

package com.permutive.gcp.auth.models

import cats.Eq
import cats.Hash
import cats.Order
import cats.Show
import cats.syntax.all._

import io.circe.Decoder
import io.circe.Encoder

final class Token(val value: String) extends AnyVal with Serializable {

  @SuppressWarnings(Array("scalafix:Disable.toString"))
  override def toString(): String = value

}

object Token {

  def apply(value: String): Token = new Token(value)

  def unapply(token: Token): Some[String] = Some(token.value)

  // Circe instances

  implicit def TokenEncoder: Encoder[Token] = Encoder[String].contramap(_.value)

  implicit def TokenDecoder: Decoder[Token] = Decoder[String].map(Token(_))

  // Cats instances

  implicit val TokenShow: Show[Token] = Show[String].contramap(_.value)

  implicit val TokenEqHashOrder: Eq[Token] with Hash[Token] with Order[Token] =
    new Eq[Token] with Hash[Token] with Order[Token] {

      override def hash(x: Token): Int = Hash[String].hash(x.value)

      override def compare(x: Token, y: Token): Int = Order[String].compare(x.value, y.value)

    }

}
