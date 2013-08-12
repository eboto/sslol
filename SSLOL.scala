/*
  Copyright 2013 The Hon. Erem Boto, Esq, DDS, MD, MBA.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
*/
package sslol

import javax.net.ssl.{SSLContext, TrustManagerFactory, X509TrustManager, SSLException, SSLSocket}
import java.io.{File, FileInputStream, FileOutputStream}
import java.security.{KeyStore, MessageDigest, SecureRandom}
import java.security.cert.{CertificateException, X509Certificate}
import scala.concurrent.{Future, ExecutionContext, Await, future}
import scala.util.matching.Regex

// This is the only stupid underscore import I should ever see in this stupid file, stupid.
import collection.JavaConversions._


/**
 * The main type in this library and the source of your company's
 * next security breach. You never need to instantiate it, just call it by
 * its companion that I strangely made extend the same trait.
 */
class SSLOL(protected val lolKeys: SSLOLKeys) extends SSLolling {
  override protected def seriousBusinessKeys = SSLOL.seriousBusinessKeys
}


object SSLOL extends SSLolling {
  override protected def lolKeys = SSLOLDB().getKeys
  override protected def seriousBusinessKeys = SSLOLDB.jreDefault.getKeys
}


/**
 * Use this to specify what sites you want to trust. Only really need it
 * if you've got an alternate port, or want to actually use this library
 * responsibly
 */
case class Site(host: String, port:Int=443, certShaStartsWith: String="") {
  private[sslol] def sha = certShaStartsWith
}


/*************************************************************************************************
 *
 * The rest of this is internal. You really shouldn't have to use it unless
 * you for some bad reason need to mock it? I don't know, or if I built this
 * library terribly. I am so sorry for what you are about to see...
 *
 ************************************************************************************************/

trait SSLolling
  extends CanTrustSitesAndProduce[SSLolling]
  with HasLolKeysAndCanProduce[SSLolling]
  with Playground
  with FunctionalPlayground
  with Handshaking
{
  def managedCerts: Seq[SSLOLCert] = {
    lolKeys.managedCerts
  }

  def store(file: File, password: String=""): SSLolling = {
    lolKeys.store(file)

    this
  }

  def store(filename: String): SSLolling = {
    lolKeys.store(new File(filename))

    this
  }

  def load(file: String, password: String = ""): SSLolling = {
    val loadedKeys = SSLOLDB(file, password).getKeys

    new SSLOL(lolKeys adding loadedKeys)
  }

  //
  // Abstract members
  //
  override protected def lolKeys: SSLOLKeys
  protected def seriousBusinessKeys: SSLOLKeys

  //
  // Playground Implementation
  //
  override protected def playgroundSSLContext = allKeys.sslContext

  //
  // Handshaking Implementations
  //
  override protected def handshakeTrustManager = {
    allKeys.trustManager
  }

  //
  // HasLolKeysAndCanProduce[SSLolling] Implementations
  //
  override protected def withLolKeys(keys: SSLOLKeys): SSLolling = {
    new SSLOL(keys)
  }

  //
  // Private members
  //
  private lazy val allKeys = seriousBusinessKeys adding lolKeys
}


private[sslol] trait CanTrustSitesAndProduce[T <: HasLolKeysAndCanProduce[T] with Handshaking] { this: T =>
  def trust(host: String): T = {
    trust(Site(host))
  }

  def trust(site: Site): T = {
    val response = shakeHandsWith(site)
    val certChainContainsSha = response.certs.find(_.shaSumStartsWith(site.sha)).isDefined

    if (!response.certsWereAccepted && certChainContainsSha) {
      this.withLolKeys(lolKeys withCerts response.certs)
    } else {
      // Either we already trusted the cert chain, or the cert chain presented to us
      // didn't contain one with the desired sha so we can't trust it
      this
    }
  }
}


private[sslol] trait HasLolKeysAndCanProduce[T] { this: T =>
  protected def lolKeys: SSLOLKeys
  protected def withLolKeys(newKeys: SSLOLKeys): T
}


trait Playground {
  private var origSslContext: Option[SSLContext] = None

  def openPlayground() {
    origSslContext = Some(SSLContext.getDefault)
    SSLContext.setDefault(playgroundSSLContext)
  }

  def closePlayground() {
    origSslContext.foreach(orig => SSLContext.setDefault(orig))
  }

  //
  // Abstract members
  //
  protected def playgroundSSLContext: SSLContext
}


private[sslol] trait FunctionalPlayground { this: Playground =>
  def inPlayground[T](operation: => Future[T])(implicit ec: ExecutionContext): Future[T] = {
    openPlayground()

    try {
      // Close the playground whether the future succeeds or fails.
      def closeAndPassThrough[T](result: T): T = { closePlayground(); result }
      operation.transform(s=closeAndPassThrough, f=closeAndPassThrough)
    } catch {
      // Close the playground if an exception got thrown in the operation while still on this thread
      case exc: Throwable =>
        closePlayground()
        throw exc
    }
  }

  def inPlayground[T](operation: => T): T = {
    openPlayground()

    try {
      operation
    } finally {
      closePlayground()
    }
  }

  //
  // Abstract members
  //
  protected def openPlayground()
  protected def closePlayground()
}


private[sslol] trait Handshaking {
  protected def handshakeTrustManager: X509TrustManager

  def shakeHandsWith(site: Site) = {
    // Initialize the memoing trustmanager that will record certificates passed in
    // for validation.
    val memo = new MemoingTrustManager(handshakeTrustManager)

    // Initialize an SSL context with our memoing trust manager and make the request.
    val sslContext = SSLContext.getInstance("TLS")
    sslContext.init(null, Array(memo), new SecureRandom)

    val canHazHandshake = _iCanHazHandshake(site.host, site.port, sslContext)
    val certs = memo.certChain.map(x509Cert => new SSLOLCert(x509Cert, site.host, site.port))

    new SSLOLCertResponse(certs, canHazHandshake)
  }

  private def _iCanHazHandshake(host: String, port: Int, sslContext: SSLContext): Boolean = {

    val socket = sslContext.getSocketFactory.createSocket(host, port).asInstanceOf[SSLSocket]
    socket.setSoTimeout(10000)

    try {
      socket.startHandshake()
      socket.close()
      true
    } catch {
      case e: SSLException => false
    }
  }
}


private[sslol] class MemoingTrustManager(tm: X509TrustManager) extends X509TrustManager {
  var certChain: Array[X509Certificate] = Array()

  override def getAcceptedIssuers: Array[X509Certificate] = tm.getAcceptedIssuers

  override def checkClientTrusted(chain: Array[X509Certificate], authType: String) = {
    tm.checkClientTrusted(chain, authType)
  }

  override def checkServerTrusted(chain: Array[X509Certificate], authType: String) {
    this.certChain = chain
    tm.checkServerTrusted(chain, authType)
  }
}

private[sslol] sealed trait KeyStoreableCert {
  def alias: String
  def cert: X509Certificate

  def subject = cert.getSubjectX500Principal
  def issuer = cert.getIssuerX500Principal

  lazy val sha1 = {
    shaDigest.update(cert.getEncoded)

    hexEncode(shaDigest.digest)
  }


  lazy val md5 = {
    md5Digest.update(cert.getEncoded)

    hexEncode(md5Digest.digest)
  }

  def shaSumStartsWith(testString: String): Boolean = {
    val cleanedTestString = testString.toLowerCase.trim.replaceAll(" ", "")

    sha1.startsWith(testString)
  }

  def addToKeystore(keyStore: KeyStore) {
    keyStore.setCertificateEntry(alias, cert)
  }

  //
  // Private members
  //
  private lazy val List(shaDigest, md5Digest) = List("sha1", "md5").map(MessageDigest.getInstance)

  private def hexEncode(toEncode: Array[Byte]) = {
    val byteStrings = for (byte <- toEncode) yield "%x".format(byte)

    byteStrings.mkString
  }
}

private[sslol] object KeyStoreableCert {
  private val keystoreAliasRegex = new Regex("sslol:host=([^:]*):port=([0-9]*)", "host", "port")

  def read(keyStore: KeyStore): Map[String, KeyStoreableCert] = {
    keyStore.aliases.foldLeft(Map.empty[String, KeyStoreableCert]) { case (certs, alias) =>
      keystoreAliasRegex.findFirstMatchIn(alias) match {
        case Some(hit) =>
          val lolCert = new SSLOLCert(
            cert=keyStore.getCertificate(alias).asInstanceOf[X509Certificate],
            host=hit.group("host"),
            port=hit.group("port").toInt
          )

          certs + (alias -> lolCert)

        case None if keyStore.isCertificateEntry(alias) =>
          val seriousCert = new SeriousBusinessCert(
            keyStore.getCertificate(alias).asInstanceOf[X509Certificate],
            alias
          )

          certs + (alias -> seriousCert)

        case None =>
          certs
      }
    }
  }
}

private[sslol] class SeriousBusinessCert(val cert: X509Certificate, val alias: String) extends KeyStoreableCert

private[sslol] class SSLOLCert(val cert: X509Certificate, host: String, port: Int) extends KeyStoreableCert {

  override def alias = {
    "sslol:host=" + host + ":port=" + port + ""
  }

  override def toString = {
    "SSLOLCert(alias=" + alias + ", subject=" + subject + ", issuer=" + issuer + ", sha1=" + sha1 + ", md5=" + md5 + ")"
  }
}

private[sslol] case class SSLOLCertResponse(certs: Seq[SSLOLCert], val certsWereAccepted: Boolean)


private[sslol] class SSLOLKeys(val certs: Map[String, KeyStoreableCert]) {
  lazy val trustManager = {
    _trustManagers(0).asInstanceOf[X509TrustManager]
  }

  lazy val sslContext = {
    val context = SSLContext.getInstance("TLS")
    context.init(null, _trustManagers, null)

    context
  }

  def adding(other: SSLOLKeys): SSLOLKeys = {
    new SSLOLKeys(this.certs ++ other.certs)
  }

  def withCert(cert: SSLOLCert): SSLOLKeys = {
    new SSLOLKeys(certs + (cert.alias -> cert))
  }

  def withCerts(certs: Seq[SSLOLCert]): SSLOLKeys = {
    certs.foldLeft(this)((accum, next) => accum.withCert(next))
  }

  def managedCerts: Seq[SSLOLCert] = {
    KeyStoreableCert.read(keyStore).values.flatMap {
      case lolCert: SSLOLCert => Some(lolCert)
      case _: SeriousBusinessCert => None
    }.toSeq
  }

  def store(file: File, password: String="") {
    val outStream = new FileOutputStream(file)
    keyStore.store(outStream, password.toArray)
    outStream.close()
  }

  //
  // Private members
  //
  private lazy val _trustManagers = {
    val defaultTrustAlgo = TrustManagerFactory.getDefaultAlgorithm
    val trustMgrFact = TrustManagerFactory.getInstance(defaultTrustAlgo)
    trustMgrFact.init(keyStore)

    trustMgrFact.getTrustManagers()
  }

  private lazy val keyStore = {
    val ks = _newKeystore
    for (aliasAndCert <- certs) ks.setCertificateEntry(aliasAndCert._1, aliasAndCert._2.cert)

    ks
  }

  private def _addAllOfKeyStore(source: KeyStore, target: KeyStore) {
    source.aliases.map(alias => (alias, keyStore.getCertificate(alias))).foreach { case (alias, cert) =>
      target.setCertificateEntry(alias, cert)
    }
  }

  private def _newKeystore = {
    val newKs = KeyStore.getInstance(KeyStore.getDefaultType)
    newKs.load(null, null)

    newKs
  }
}


private[sslol] class SSLOLDB(file: File, password: String="") {
  def getKeys: SSLOLKeys = {
    val passwordAsArray = password.toArray
    val keyStore = if (file.isFile) {
      val certsIn = new FileInputStream(file)
      val keyStore = KeyStore.getInstance(KeyStore.getDefaultType())
      keyStore.load(certsIn, passwordAsArray)
      certsIn.close()

      keyStore
    } else {
      val keyStore = KeyStore.getInstance(KeyStore.getDefaultType)
      keyStore.load(null, passwordAsArray)

      keyStore
    }

    new SSLOLKeys(KeyStoreableCert read keyStore)
  }
}


private[sslol] object SSLOLDB {
  lazy val jreDefault: SSLOLDB = {
    import File.{separatorChar => sep}
    val javaHome = System.getProperty("java.home")
    val cacertsDir = javaHome + sep + "lib" + sep + "security"
    val cacertsCandidates = List( "jssecacerts", "cacerts").map(name => new File(cacertsDir + sep + name))

    val maybeCertsFile = cacertsCandidates.foldLeft(None: Option[File]) { (prevResult, candidate) =>
      if (prevResult.isEmpty && candidate.isFile) Some(candidate) else prevResult
    }

    val certsFile = maybeCertsFile.getOrElse {
      throw new RuntimeException(
        "We wants your default cacerts file and can't finds. Find it and put it in one of these places:\n" +
        cacertsCandidates.map(_.getAbsolutePath).mkString(",\n")
      )
    }

    new SSLOLDB(certsFile, "changeit")
  }

  def apply(cacertsFile: String = "sslolcacerts", password: String =""): SSLOLDB = {
    import File.{separatorChar => sep}

    new SSLOLDB(new File(cacertsFile), password)
  }
}