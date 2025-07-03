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

final class ClientEmail(val value: String) extends AnyVal with Serializable {

  @SuppressWarnings(Array("scalafix:Disable.toString"))
  override def toString(): String = value

}

object ClientEmail {

  def apply(value: String): ClientEmail = new ClientEmail(value)

  def unapply(clientEmail: ClientEmail): Some[String] = Some(clientEmail.value)

  // Circe instances

  implicit def ClientEmailEncoder: Encoder[ClientEmail] = Encoder[String].contramap(_.value)

  implicit def ClientEmailDecoder: Decoder[ClientEmail] = Decoder[String].map(ClientEmail(_))

  // Cats instances

  implicit val ClientEmailShow: Show[ClientEmail] = Show[String].contramap(_.value)

  implicit val ClientEmailEqHashOrder: Eq[ClientEmail] with Hash[ClientEmail] with Order[ClientEmail] =
    new Eq[ClientEmail] with Hash[ClientEmail] with Order[ClientEmail] {

      override def hash(x: ClientEmail): Int = Hash[String].hash(x.value)

      override def compare(x: ClientEmail, y: ClientEmail): Int = Order[String].compare(x.value, y.value)

    }

}
