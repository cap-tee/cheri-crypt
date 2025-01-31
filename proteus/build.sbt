//This is the project build file
//Note: If you make a change to this file in IntelliJ you have to close the project and re-open
// for changes to have an effect

name := "Proteus"
version := "0.1"

scalaVersion := "2.11.12"
val spinalVersion = "1.7.3"

fork := true

libraryDependencies ++= Seq(
  "com.github.spinalhdl" % "spinalhdl-core_2.11" % spinalVersion,
  "com.github.spinalhdl" % "spinalhdl-lib_2.11" % spinalVersion,
  compilerPlugin("com.github.spinalhdl" % "spinalhdl-idsl-plugin_2.11" % spinalVersion)
)

