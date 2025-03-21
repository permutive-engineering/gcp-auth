ThisBuild / scalaVersion           := "2.13.15"
ThisBuild / crossScalaVersions     := Seq("2.12.20", "2.13.15", "3.3.4")
ThisBuild / organization           := "com.permutive"
ThisBuild / versionPolicyIntention := Compatibility.BinaryAndSourceCompatible

addCommandAlias("ci-test", "fix --check; versionPolicyCheck; mdoc; publishLocal; +test")
addCommandAlias("ci-docs", "github; mdoc; headerCreateAll")
addCommandAlias("ci-publish", "versionCheck; github; ci-release")

lazy val documentation = project
  .enablePlugins(MdocPlugin)
  .dependsOn(`gcp-auth`, `gcp-auth-pureconfig`)

lazy val `gcp-auth` = module
  .settings(libraryDependencies += "com.auth0" % "java-jwt" % "4.4.0")
  .settings(libraryDependencies += "com.github.jwt-scala" %% "jwt-circe" % "10.0.1")
  .settings(libraryDependencies += "com.permutive" %% "refreshable" % "2.0.0")
  .settings(libraryDependencies += "org.http4s" %% "http4s-client" % "0.23.29")
  .settings(libraryDependencies += "org.http4s" %% "http4s-circe" % "0.23.29")
  .settings(libraryDependencies += "com.alejandrohdezma" %% "http4s-munit" % "1.1.0" % Test)
  .settings(Test / fork := true)

lazy val `gcp-auth-pureconfig` = module
  .settings(libraryDependencies += "com.github.pureconfig" %% "pureconfig-core" % "0.17.8")
  .settings(libraryDependencies += "com.alejandrohdezma" %% "http4s-munit" % "1.1.0" % Test)
  .settings(Test / fork := true)
  .dependsOn(`gcp-auth`)
