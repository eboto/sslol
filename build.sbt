scalaVersion := "2.9.3"

libraryDependencies ++= Seq(
  "org.scalatest" %% "scalatest" % "1.9.1" % "test",
  "org.mockito" % "mockito-all" % "1.9.5" % "test",
  "org.specs2" %% "specs2" % "1.12.4.1" % "test"
)

scalaSource in Test <<= baseDirectory(_ / "tests") // 'cause screw convention

