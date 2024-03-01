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

final class ClientSecret(val value: String) extends AnyVal with Serializable {

  @SuppressWarnings(Array("scalafix:Disable.toString"))
  override def toString(): String = value

}

object ClientSecret {

  def apply(value: String): ClientSecret = new ClientSecret(value)

  def unapply(clientSecret: ClientSecret): Some[String] = Some(clientSecret.value)

  // Circe instances

  implicit def ClientSecretEncoder: Encoder[ClientSecret] = Encoder[String].contramap(_.value)

  implicit def ClientSecretDecoder: Decoder[ClientSecret] = Decoder[String].map(ClientSecret(_))

  // Cats instances

  implicit val ClientSecretShow: Show[ClientSecret] = Show[String].contramap(_.value)

  implicit val ClientSecretEqHashOrder: Eq[ClientSecret] with Hash[ClientSecret] with Order[ClientSecret] =
    new Eq[ClientSecret] with Hash[ClientSecret] with Order[ClientSecret] {

      override def hash(x: ClientSecret): Int = Hash[String].hash(x.value)

      override def compare(x: ClientSecret, y: ClientSecret): Int = Order[String].compare(x.value, y.value)

    }

}
