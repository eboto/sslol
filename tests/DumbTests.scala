package sslol

import javax.net.ssl.{SSLContext, TrustManagerFactory, X509TrustManager, SSLException, SSLSocket}
import java.net.URL
import java.io.{File, FileInputStream, FileOutputStream}
import java.security.{KeyStore, MessageDigest, SecureRandom}
import java.security.cert.{CertificateException, X509Certificate}
import scala.concurrent.{Future, ExecutionContext, Await, future}
import play.api.libs.ws.WS
import scala.concurrent.duration.Duration
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
  behavior of "FunctionalPlayground.inPlayground (synchronous)"

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
    there was no (playground.delegate).openPlayground()

    playground inPlayground {
      there was one (playground.delegate).openPlayground()
      there was no (playground.delegate).closePlayground()
    }

    there was one (playground.delegate).closePlayground()
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

    there was one (playground.delegate).openPlayground
    there was one (playground.delegate).closePlayground
  }

  behavior of "FunctionalPlayground.inPlayground (async)"
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
    there was no (playground.delegate).closePlayground()
    there was one (playground.delegate).openPlayground()

    val futFinalResult = for (result <- futFirstResult) yield {
      there was one (playground.delegate).closePlayground()
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
    there was no (playground.delegate).closePlayground()
    there was one (playground.delegate).openPlayground()

    evaluating (_await(futFirstResult)) should produce [BearsException]
    there was one (playground.delegate).closePlayground()
  }

  private def _await[T] = Await.result(_: Future[T], Duration.Inf)

  def _testPlayground = {
    new FunctionalPlayground {
      override val playground = mock[Playground]
      val delegate = playground
    }
  }


  class BearsException extends RuntimeException
}

class MemoingTrustManagerSpecification extends SSLOLSpec {
  behavior of "MemoingTrustManager"

  it should "delegate all calls to its internal trustmanager" in {
    val delegate = mock[X509TrustManager]

    val underTest = new MemoingTrustManager(delegate)
    val mockCertChain = Array.empty[X509Certificate]
    val authType = "SeriousBusinessPasswordAuth"

    underTest.getAcceptedIssuers
    there was one (delegate).getAcceptedIssuers

    underTest.checkClientTrusted(mockCertChain, authType)
    there was one (delegate).checkClientTrusted(mockCertChain, authType)

    underTest.checkServerTrusted(mockCertChain, authType)
    there was one (delegate).checkServerTrusted(mockCertChain, authType)
  }

  behavior of "MemoingTrustManager.checkServerTrusted"
  it should "ferret away the chain provided to it" in {
    val underTest = new MemoingTrustManager(mock[X509TrustManager])
    val chain = Array(mock[X509Certificate])

    underTest.checkServerTrusted(chain, "SeriousBusinessAuthType")

    underTest.certChain should be (chain)
  }
}


class CanTrustSitesSpecification extends SSLOLSpec {
  behavior of "trust"
  it should "download the certs from the cite and store them away in a copy if they werent trusted" in {
    val underTest = TestTruster()
    val cert = _mockCertWithAliasAndShasum
    val handshakeResponse = HandshakeResponse(Seq(cert), false)

    underTest.handshaking.shakeHands(site) returns handshakeResponse

    val result = underTest trust site
    result.lolKeys.contains(cert) should be (true)
  }

  it should "not store copies of sites that were already trusted" in {
    val underTest = TestTruster()
    val cert = _mockCertWithAliasAndShasum
    val handshakeResponse = HandshakeResponse(Seq(cert), true)
    underTest.handshaking.shakeHands(site) returns handshakeResponse

    val result = underTest trust site
    result.lolKeys.contains(cert) should be (false)
  }

  def _mockCertWithAliasAndShasum = {
    val cert = mock[SSLOLCert]
    cert.alias returns ("alias")
    cert.sha1 returns (siteSha)
    cert.shaSumStartsWith(siteSha) returns true

    cert
  }

  val siteSha = "abc"
  val site = Site("www.google.com", certShaStartsWith=siteSha)

  case class TestTruster(lolKeys: SSLOLKeys = new SSLOLKeys()) extends CanTrustSites[TestTruster] with HasLolKeys[TestTruster] {
    override val hasLolKeys = this
    override val handshaking = mock[Handshaking]

    override def withLolKeys(keys: SSLOLKeys) = this.copy(keys)
  }
}


class KeyStoreableCertSpecification extends SSLOLSpec {
  "sha1 and md5" should "return the correct hashes of the encoded certificate" in {
    val cert = _certWithEncodedContents("the encoded contents of a cert")

    // These hashes were created via
    //   printf 'the encoded contents of a cert' | shasum -a 1
    //   printf 'the encoded contents of a cert' | md5
    cert.sha1 should be ("26b66253de624bfb99e827aa17ee69b6e07d72b2")
    cert.md5 should be ("25d4afb0473131b1d3fa3faec4b95fe6")
  }

  "shaSumStartsWith" should "return true when the sha hash starts with the provided prefix" in {
    val cert = _certWithEncodedContents("the encoded contents of a cert")

    cert.shaSumStartsWith("26b66") should be (true)
    cert.shaSumStartsWith("26 B6 6") should be (true)
    cert.shaSumStartsWith("26b65") should be (false)
  }

  "addToKeystore" should "add the contained X509Certificate" in {
    // Look, I would love to write this test but I can't mock keystore
    // so I'm not going to write it.
  }

  def _newCert(theAlias: String="test alias") = new SeriousBusinessCert(
    x509Cert=mock[X509Certificate],
    alias=theAlias
  )

  private def _certWithEncodedContents(contents: String) = {
    val cert = _newCert()
    val bytes = contents.getBytes("UTF-8")

    cert.x509Cert.getEncoded returns bytes

    cert
  }

}

class HandshakingSpecification extends SSLOLSpec {
  "shakeHands" should "receive the certs from a site" in RequireInternetConnection {
    // Compare against the LinkedIn cert...meh this'll fail eventually
    val response = _jreDefaultHandshake("www.linkedin.com")
    response.certs(0).sha1 should be ("1b9f9fcdd6dcca1fff5086562998afb10cde389")
  }

  it should "return true for already trusted websites" in RequireInternetConnection {
    val response = _jreDefaultHandshake("www.linkedin.com")
    response.handshakeSucceeded should be (true)
  }

  it should "return false for untrusted websites" in RequireInternetConnection {
    val handshaking = new Handshaking { def handshakeTrustManager = new SSLOLKeys().trustManager }
    val response = handshaking shakeHands Site("www.linkedin.com")

    response.handshakeSucceeded should be (false)
  }

  def _jreDefaultHandshake(siteUrl: String) = {
    val handshaking = _jreDefaultHandshaking
    handshaking shakeHands Site(siteUrl)
  }
  def _jreDefaultHandshaking = new Handshaking { def handshakeTrustManager = SSLOLDB.jreDefault.getKeys.trustManager }
}


class IntegrationSpecification extends SSLOLSpec {
  behavior of "SSLOL"

  it should "enable connections to untrusted sources blindly" in RequireInternetConnection {

    _SSLOLWithoutCertificateAuthorities trust "www.google.com" inPlayground {
      evaluating (_tryConnect("https://www.linkedin.com")) should produce [java.net.ConnectException]
    }

    _tryConnect("https://www.linkedin.com") // Throws SSLException on failure

  }

  def _tryConnect(siteUrl: String): Unit = {
    Await.result(WS.url(siteUrl).get(), Duration.Inf)
  }

  def _SSLOLWithoutCertificateAuthorities = {
    new SSLolling {
      val lolKeys = new SSLOLKeys()
      val seriousBusinessKeys = new SSLOLKeys()
    }
  }
}

object RequireInternetConnection extends FlatSpec {
  def apply[T](operation: => T): Any = {
    try {
      operation
    } catch {
      case e: java.net.UnknownHostException => pending
      case e: java.net.NoRouteToHostException => pending
    }
  }
}