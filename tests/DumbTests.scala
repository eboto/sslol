package sslol

import org.scalatest.FlatSpec
import org.scalatest.matchers.ShouldMatchers

class FunctionalPlaygroundSpec extends FlatSpec with ShouldMatchers {
  behavior of "FunctionalPlayground"

  it should "herp and derp" in {
    1 should be (2)
  }
}