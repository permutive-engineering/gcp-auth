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

package com.permutive.gcp.auth.models

import cats.Eq
import cats.Hash
import cats.Order
import cats.Show
import cats.syntax.all._

import io.circe.Decoder
import io.circe.Encoder

final class ExpiresIn(val value: Long) extends AnyVal with Serializable {

  @SuppressWarnings(Array("scalafix:Disable.toString"))
  override def toString(): String = value.show

}

object ExpiresIn {

  def apply(value: Long): ExpiresIn = new ExpiresIn(value)

  def unapply(expiresIn: ExpiresIn): Some[Long] = Some(expiresIn.value)

  // Circe instances

  implicit def ExpiresInEncoder: Encoder[ExpiresIn] = Encoder[Long].contramap(_.value)

  implicit def ExpiresInDecoder: Decoder[ExpiresIn] = Decoder[Long].map(ExpiresIn(_))

  // Cats instances

  implicit val ExpiresInShow: Show[ExpiresIn] = Show[Long].contramap(_.value)

  implicit val ExpiresInEqHashOrder: Eq[ExpiresIn] with Hash[ExpiresIn] with Order[ExpiresIn] =
    new Eq[ExpiresIn] with Hash[ExpiresIn] with Order[ExpiresIn] {

      override def hash(x: ExpiresIn): Int = Hash[Long].hash(x.value)

      override def compare(x: ExpiresIn, y: ExpiresIn): Int = Order[Long].compare(x.value, y.value)

    }

}
