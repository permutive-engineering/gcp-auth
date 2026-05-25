ThisBuild / scalaVersion           := "2.13.18"
ThisBuild / crossScalaVersions     := Seq("2.13.18", "3.3.7")
ThisBuild / organization           := "com.permutive"
ThisBuild / versionPolicyIntention := Compatibility.None

addCommandAlias("ci-test", "fix --check; versionPolicyCheck; mdoc; publishLocal; +test")
addCommandAlias("ci-docs", "github; mdoc; headerCreateAll")
addCommandAlias("ci-publish", "versionCheck; github; ci-release")

lazy val documentation = project
  .enablePlugins(MdocPlugin)
  .dependsOn(`gcp-auth`, `gcp-auth-pureconfig`, `gcp-auth-kafka`)

lazy val `gcp-auth` = module
  .settings(Test / fork := true)

lazy val `gcp-auth-pureconfig` = module
  .settings(Test / fork := true)
  .dependsOn(`gcp-auth`)

lazy val `gcp-auth-kafka` = module
  .settings(Test / fork := true)
  .dependsOn(`gcp-auth`)
