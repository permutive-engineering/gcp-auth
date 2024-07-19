Methods to authenticate with Google services over HTTP

---

- [Installation](#installation)
- [Usage](#usage)
  - [Available token providers](#available-token-providers)
    - [Identity](#identity)
    - [Service-Account](#service-account)
    - [User-Account](#user-account)
  - [Creating and auto-refreshing & cached `TokenProvider`](#creating-and-auto-refreshing--cached-tokenprovider)
  - [Creating an auto-authenticated http4s `Client`](#creating-an-auto-authenticated-http4s-client)
  - [Loading a different `TokenProvider` depending on the environment with `pureconfig`](#loading-a-different-tokenprovider-depending-on-the-environment-with-pureconfig)
- [Contributors to this project](#contributors-to-this-project)

## Installation

Add the following line to your `build.sbt` file:

```sbt
libraryDependencies += "com.permutive" %% "gcp-auth" % "1.1.0"
```

The library is published for Scala versions: `2.12`, `2.13` and `3`.

## Usage

This library provides a class `TokenProvider` that is able to retrieve a
specific type of access token from [Google OAuth 2.0] API.

### Available token providers


#### Identity

Retrieves an [Identity Token] using Google's metadata server for a specific audience.

Identity tokens can be used for calling Cloud Run services.

**Important!** This method can only be run from within a workload container in
GCP. The call will fail otherwise.

```scala
import com.permutive.gcp.auth.TokenProvider

val audience = uri"https://my-run-app.a.run.app"

TokenProvider.identity[IO](httpClient, audience)
```

#### Service-Account

Retrieves a [Google Service Account Token] either via the
[instance metadata API] (if running from a GCP workload) or using a
specific service account file.

```scala
import com.permutive.gcp.auth.TokenProvider
import com.permutive.gcp.auth.models.ClientEmail

// Retrieves a workload service account token using
// Google's metadata server.
TokenProvider.serviceAccount[IO](httpClient)

// Retrieves a service account token using a specific
// file and scopes
TokenProvider.serviceAccount[IO](
    pathToServiceAccountFile,
    scope = "https://www.googleapis.com/auth/bigquery" :: Nil,
    httpClient
)

// Retrieves a service account token using a specific
// email/key/scopes
TokenProvider.serviceAccount[IO](
    ClientEmail("my@example.com"),
    privateKey: RSAPrivateKey,
    scope = "https://www.googleapis.com/auth/bigquery" :: Nil,
    httpClient
)
```

#### User-Account

Retrieves a [Google User Account Token] either using the application default
credentials or from a specific path.

```scala
import com.permutive.gcp.auth.TokenProvider
import com.permutive.gcp.auth.models.ClientId
import com.permutive.gcp.auth.models.ClientSecret
import com.permutive.gcp.auth.models.RefreshToken

// Retrieves a user account token using a specific file
// for the secrets and token
TokenProvider.userAccount[IO](
    pathToClientSecretsPath,
    pathToRefreshTokenPath, 
    httpClient
)

// Retrieves a service account token using a specific
// client-id/client-secret/refresh-token
TokenProvider.userAccount[IO](
    ClientId("client-id"),
    ClientSecret("client-secret"),
    RefreshToken("refresh-token"),
    httpClient
)

// Retrieves a user account token using the application
// default credentials
TokenProvider.userAccount[IO](httpClient)
```

### Creating and auto-refreshing & cached `TokenProvider`

You can use `TokenProvider.cached` to create an auto-refreshing & cached
version of any `TokenProvider` that will cache each token generated for
the lifespan of that token and then generates a new one.

```scala
import com.permutive.gcp.auth.TokenProvider

val tokenProvider =
    TokenProvider.userAccount[IO](httpClient)

TokenProvider.cached[IO]
    .safetyPeriod(4.seconds) // 1.
    .onRefreshFailure { case (_, _) => IO.unit }
    .onExhaustedRetries(_ => IO.unit)
    .onNewToken { case (_, _) => IO.unit }
    .retryPolicy(constantDelay[IO](200.millis)) // 2.
    .build(tokenProvider)

/**
 * 1. How much time less than the indicated expiry to
 *    cache a token for
 * 2. Defaults to 5 retries with a delay between each
 *    of 200 milliseconds.
 */
```

### Creating an auto-authenticated http4s `Client`

Once you have a `TokenProvider` created, you can use its `clientMiddleware`
method to wrap an http4s' `Client` ensuring every request coming out from it
will contain an `Authorization` header with the access token provided by the
`TokenProvider`.

```scala
import com.permutive.gcp.auth.TokenProvider

TokenProvider
    .userAccount[IO](httpClient)
    .map(_.clientMiddleware(httpClient))
```

### Loading a different `TokenProvider` depending on the environment with `pureconfig`

The library also provides a [pureconfig] integration that simplifies the process
of using a different `TokenProvider` on different environments. For example, you
may want to use the workload service-account when running from GCP, but would
want to use a user-account when running your service locally, or use a no-op
access token when running in tests. You can simplify that process by loading
the appropriate `TokenProvider` using pureconfig:

1. Add the following line to your `build.sbt` file:

```sbt
libraryDependencies += "com.permutive" %% "gcp-auth-pureconfig" % "1.1.0"
```

2. Use the following type in your configuration class:

```scala
import com.permutive.gcp.auth.pureconfig._

case class Config(tokenType: TokenType)
```

3. In your `application.conf` file provide the appropriate type:

```conf
token-type = "user-account"
token-type = "service-account"
token-type = "no-op"
```

4. When you want to instantiate your `TokenProvider` simply use:


```scala
val tokenProvider = config.tokenType.tokenProvider(httpClient)
```

## Contributors to this project

| <a href="https://github.com/alejandrohdezma"><img alt="alejandrohdezma" src="https://avatars.githubusercontent.com/u/9027541?v=4&s=120" width="120px" /></a> |
| :--: |
| <a href="https://github.com/alejandrohdezma"><sub><b>alejandrohdezma</b></sub></a> |

[Google OAuth 2.0]: https://developers.google.com/identity/protocols/OAuth2
[`TokenProvider`]: modules/google-auth/src/main/scala/com/permutive/google/auth/TokenProvider.scala
[Google Service Account Token]: https://developers.google.com/identity/protocols/OAuth2ServiceAccount
[Google User Account Token]: https://developers.google.com/identity/protocols/OAuth2WebServer
[Identity Token]: https://cloud.google.com/run/docs/securing/service-identity#fetching_identity_and_access_tokens_using_the_metadata_server
[instance metadata API]: https://cloud.google.com/compute/docs/access/authenticate-workloads
[pureconfig]: https://pureconfig.github.io