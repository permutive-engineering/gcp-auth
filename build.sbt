ThisBuild / scalaVersion       := "2.13.12"
ThisBuild / crossScalaVersions := Seq("2.13.12", "3.3.0")
ThisBuild / organization       := "com.permutive"

addCommandAlias("ci-test", "fix --check; mdoc; publishLocal; +test")
addCommandAlias("ci-docs", "github; mdoc; headerCreateAll")
addCommandAlias("ci-publish", "github; ci-release")

lazy val documentation = project
  .enablePlugins(MdocPlugin)
  .dependsOn(`gcp-auth`, `gcp-auth-pureconfig`)

lazy val `gcp-auth` = module
  .settings(libraryDependencies += "com.auth0" % "java-jwt" % "4.4.0")
  .settings(libraryDependencies += "com.github.jwt-scala" %% "jwt-circe" % "9.4.5")
  .settings(libraryDependencies += "com.permutive" %% "refreshable" % "1.1.0")
  .settings(libraryDependencies += "org.http4s" %% "http4s-client" % "0.23.24")
  .settings(libraryDependencies += "org.http4s" %% "http4s-circe" % "0.23.24")

lazy val `gcp-auth-pureconfig` = module
  .settings(libraryDependencies += "com.github.pureconfig" %% "pureconfig-core" % "0.17.4")
  .dependsOn(`gcp-auth`)
