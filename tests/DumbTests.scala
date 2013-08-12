package sslol

import javax.net.ssl.{SSLContext, TrustManagerFactory, X509TrustManager, SSLException, SSLSocket}
import java.io.{File, FileInputStream, FileOutputStream}
import java.security.{KeyStore, MessageDigest, SecureRandom}
import java.security.cert.{CertificateException, X509Certificate}
import scala.concurrent.{Future, ExecutionContext, Await, future}

import org.scalatest.FlatSpec
import org.scalatest.matchers.ShouldMatchers
import org.specs2.mock.Mockito
import org.specs2.mock.mockito.MockitoFunctions


trait SSLOLSpec extends FlatSpec with ShouldMatchers with Mockito with MockitoFunctions

class PlaygroundSpecification extends SSLOLSpec {
  behavior of "Playground"

  it should "swap in and out the default SSL context with its own on open and close" in {
    val origSSLContext = SSLContext.getDefault
    val mockSSLContext = mock[SSLContext]
    val playground = new Playground { val playgroundSSLContext = mockSSLContext }

    SSLContext.getDefault should be (origSSLContext)

    playground.openPlayground()
    SSLContext.getDefault should be (mockSSLContext)

    playground.closePlayground()
    SSLContext.getDefault should be (origSSLContext)
  }
}


class FunctionalPlaygroundSpecification extends SSLOLSpec {
  behavior of "inPlayground (synchronous)"

  it should "return the parameterized computation's return value" in {
    val expected = 1
    val actual = _testPlayground inPlayground {
      expected
    }

    actual should be (expected)
  }

  it should "propagate exceptions from the parameterized computation" in {
    val thrown = new BearsException

    evaluating(_testPlayground inPlayground { throw thrown; 1 }) should produce [BearsException]
  }

  it should "open and close around the parameterized computation when no exceptions are thrown" in {
    // Set up
    val playground = _testPlayground

    val expectedResult = 2

    // Run and test expectations
    there was no (playground).openPlayground()

    playground inPlayground {
      there was one (playground).openPlayground()
      there was no (playground).closePlayground()
    }

    there was one (playground).closePlayground()
  }

  it should "open and close around the parameterized computation when exceptions are thrown" in {
    val playground = _testPlayground

    try {
      playground inPlayground {
        throw new BearsException

        1
      }
    } catch {
      case e: BearsException => "Jeez...I really don't have much to do here."
    }

    there was one (playground).openPlayground
    there was one (playground).closePlayground
  }

  behavior of "inPlayground (async)"
  import scala.concurrent.ExecutionContext.Implicits.global
  import scala.concurrent.{Future, Await, future}
  import scala.concurrent.duration.Duration


  it should "return the parameterized computation's return value" in {
    val expected = 1

    val result = _testPlayground inPlayground Future.successful(expected)

    _await(result) should be (expected)
  }

  it should "propagate exceptions in the parameterized computation" in {
    val result = _testPlayground inPlayground Future.failed(new BearsException)

    evaluating (_await(result)) should produce [BearsException]
  }

  it should "produce a future that closes the playground before executing any sequenced futures in success case" in {
    val playground = _testPlayground
    val firstResultValue = 1
    val futFirstResult = _testPlayground inPlayground {
      future {
        Thread.sleep(200)

        firstResultValue
      }
    }
    there was no (playground).closePlayground()
    there was one (playground).openPlayground()

    val futFinalResult = for (result <- futFirstResult) yield {
      there was one (playground).closePlayground()
      result should be (firstResultValue)

      2
    }

    _await(futFinalResult) should be (2)
  }

  it should "open and close at the correct times relative to the future if exception thrown" in {
    val playground = _testPlayground

    val futFirstResult = _testPlayground inPlayground {
      future {
        Thread.sleep(200)

        throw new BearsException
      }
    }
    there was no (playground).closePlayground()
    there was one (playground).openPlayground()

    evaluating (_await(futFirstResult)) should produce [BearsException]
    there was one (playground).closePlayground()
  }

  private def _await[T] = Await.result(_: Future[T], Duration.Inf)

  def _testPlayground = {
    class TestPlayground extends Playground with FunctionalPlayground {
      override val playgroundSSLContext = mock[SSLContext]
    }

    val playground = spy(new TestPlayground())

    doNothing.when(playground).openPlayground()
    doNothing.when(playground).closePlayground()

    playground
  }

  class BearsException extends RuntimeException
}
