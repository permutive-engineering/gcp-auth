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

package com.permutive.gcp.auth.models

import cats.Eq
import cats.Hash
import cats.Order
import cats.Show
import cats.syntax.all._

import io.circe.Decoder
import io.circe.Encoder

final class ClientId(val value: String) extends AnyVal with Serializable {

  @SuppressWarnings(Array("scalafix:Disable.toString"))
  override def toString(): String = value

}

object ClientId {

  def apply(value: String): ClientId = new ClientId(value)

  def unapply(clientId: ClientId): Some[String] = Some(clientId.value)

  // Circe instances

  implicit def ClientIdEncoder: Encoder[ClientId] = Encoder[String].contramap(_.value)

  implicit def ClientIdDecoder: Decoder[ClientId] = Decoder[String].map(ClientId(_))

  // Cats instances

  implicit val ClientIdShow: Show[ClientId] = Show[String].contramap(_.value)

  implicit val ClientIdEqHashOrder: Eq[ClientId] with Hash[ClientId] with Order[ClientId] =
    new Eq[ClientId] with Hash[ClientId] with Order[ClientId] {

      override def hash(x: ClientId): Int = Hash[String].hash(x.value)

      override def compare(x: ClientId, y: ClientId): Int = Order[String].compare(x.value, y.value)

    }

}
