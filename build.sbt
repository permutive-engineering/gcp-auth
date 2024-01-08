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

lazy val `gcp-auth-pureconfig` = module
  .dependsOn(`gcp-auth`)
