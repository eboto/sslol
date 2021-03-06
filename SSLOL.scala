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

import javax.net.ssl.{SSLContext, TrustManagerFactory, SSLEngine, X509TrustManager, SSLException, SSLSocket, SSLContextSpi}
import java.io.{File, FileInputStream, FileOutputStream}
import java.security.{KeyStore, MessageDigest, SecureRandom, Provider}
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
class SSLOL(protected[sslol] val lolKeys: SSLOLKeys, protected val seriousBusinessKeys: SSLOLKeys) extends SSLolling

object SSLOL extends SSLolling {
  override protected[sslol] def lolKeys = SSLOLDB().getKeys
  override protected def seriousBusinessKeys = SSLOLDB.jreDefault.getKeys

  val DEFAULT_PASSWORD = "changeit"

  def initialize() = Playground.ensureInitialized

  /**
   * Creates an SSLOL whose playground doesn't even trust the JRE defaults CAs.
   *
   * This is useful if you only want to trust one specific site, and no others.
   *
   * Using it alone will produce an error, so don't use it unless you will be adding
   * sites first.
   */
  val empty: SSLolling = {
    new SSLolling {
      override protected[sslol] def lolKeys = SSLOLKeys.empty
      override protected def seriousBusinessKeys = SSLOLKeys.empty
    }
  }
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
  extends CanTrustSites[SSLolling]
  with HasLolKeys[SSLolling]
  with Playground
  with FunctionalPlayground
  with Handshaking
{
  def managedCerts: Seq[SSLOLCert] = {
    lolKeys.managedCerts
  }

  def store(file: File, password: String=SSLOL.DEFAULT_PASSWORD): SSLolling = {
    lolKeys.store(file)

    this
  }

  def store(filename: String): SSLolling = {
    lolKeys.store(new File(filename))

    this
  }

  def load(file: String, password: String = SSLOL.DEFAULT_PASSWORD): SSLolling = {
    val loadedKeys = SSLOLDB(file, password).getKeys

    new SSLOL(lolKeys adding loadedKeys, seriousBusinessKeys)
  }

  //
  // Abstract members
  //
  override protected[sslol] def lolKeys: SSLOLKeys
  protected def seriousBusinessKeys: SSLOLKeys

  //
  // Cake wiring
  //
  override protected val playground = this
  override protected val hasLolKeys = this
  override protected val handshaking = this

  //
  // Playground Implementation
  //
  override protected def playgroundTrustManager = {
    allKeys.trustManager
  }

  //
  // Handshaking Implementations
  //
  override protected def handshakeTrustManager = {
    allKeys.trustManager
  }

  //
  // HasLolKeys[SSLolling] Implementations
  //
  override protected[sslol] def withLolKeys(keys: SSLOLKeys): SSLolling = {
    new SSLOL(keys, seriousBusinessKeys)
  }

  //
  // Private members
  //
  private lazy val allKeys = seriousBusinessKeys adding lolKeys
}


private[sslol] trait CanTrustSites[T] { this: T =>
  protected def hasLolKeys: HasLolKeys[T]
  protected def handshaking: Handshaking

  def trust(host: String): T = {
    trust(Site(host))
  }

  def trust(site: Site): T = {
    val response = handshaking shakeHands site
    val certChainContainsSha = response.certs.find(_.shaSumStartsWith(site.sha)).isDefined
    val doAddReceivedKeys = (!response.handshakeSucceeded) && certChainContainsSha

    if (doAddReceivedKeys && !response.certs.isEmpty) {
      hasLolKeys.withLolKeys(hasLolKeys.lolKeys.withCert(response.certs(0)))
    } else {
      // Either we already trusted the cert chain, or the cert chain presented to us
      // didn't contain one with the desired sha so we can't trust it
      this
    }
  }
}


private[sslol] trait HasLolKeys[T] { this: T =>
  protected[sslol] def lolKeys: SSLOLKeys
  protected[sslol] def withLolKeys(newKeys: SSLOLKeys): T
}


trait Playground {
  private var origTrustManager: Option[X509TrustManager] = None

  def openPlayground() {
    Playground.ensureInitialized()
    origTrustManager = Some(Playground.currentTrustManager)
    Playground.setJVMTrustManager(playgroundTrustManager)
  }

  def closePlayground() {
    origTrustManager.foreach(orig => Playground.setJVMTrustManager(orig))
  }

  //
  // Abstract members
  //
  protected def playgroundTrustManager: X509TrustManager
}


private[sslol] object Playground {
  def currentTrustManager = lolTrustManager.delegate

  def setJVMTrustManager(tm: X509TrustManager) {
    // Invalidate sessions made during reign of previous TrustManager
    val sessions = sslolContext.getClientSessionContext

    for {
      sessionId <- sessions.getIds
      session <- Option(sessions.getSession(sessionId))
    } {
      session.invalidate()
    }

    lolTrustManager.delegate = tm
  }

  private val lolTrustManager = {
    new ShimmableTrustManager(SSLOLDB.jreDefault.getKeys.trustManager)
  }

  private val sslolContext = {
    val currentDefault = SSLContext.getDefault
    val sslolContext = SSLContext.getInstance("TLS")
    sslolContext.init(null, Array(lolTrustManager), new SecureRandom)

    sslolContext
  }

  def ensureInitialized() {
    SSLContext.setDefault(sslolContext)
  }
}


private[sslol] trait FunctionalPlayground {
  protected def playground: Playground

  def inPlayground[T](operation: => Future[T])(implicit ec: ExecutionContext): Future[T] = {
    playground.openPlayground()

    try {
      // Close the playground whether the future succeeds or fails.
      def closeAndPassThrough[T](result: T): T = { playground.closePlayground(); result }
      operation.transform(s=closeAndPassThrough, f=closeAndPassThrough)
    } catch {
      // Close the playground if an exception got thrown in the operation while still on this thread
      case exc: Throwable =>
        playground.closePlayground()
        throw exc
    }
  }

  def inPlayground[T](operation: => T): T = {
    playground.openPlayground()

    try {
      operation
    } finally {
      playground.closePlayground()
    }
  }
}


private[sslol] trait Handshaking {
  protected def handshakeTrustManager: X509TrustManager

  def shakeHands(site: Site) = {
    // Initialize the memoing trustmanager that will record certificates passed in
    // for validation.
    val memo = new MemoingTrustManager(handshakeTrustManager)

    // Initialize an SSL context with our memoing trust manager and make the request.
    val sslContext = SSLContext.getInstance("TLS")
    sslContext.init(null, Array(memo), new SecureRandom)

    val canHazHandshake = _iCanHazHandshake(site.host, site.port, sslContext)
    val certs = memo.certChain.map(x509Cert => new SSLOLCert(x509Cert, site.host, site.port))

    new HandshakeResponse(certs, canHazHandshake)
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


private[sslol] class ShimmableTrustManager(var _delegate: X509TrustManager) extends X509TrustManager {
  require(!_delegate.isInstanceOf[ShimmableTrustManager])

  def delegate = _delegate
  def delegate_=(other: X509TrustManager) {
    require(!other.isInstanceOf[ShimmableTrustManager])

    _delegate = other
  }

  override def getAcceptedIssuers: Array[X509Certificate] = _delegate.getAcceptedIssuers

  override def checkClientTrusted(chain: Array[X509Certificate], authType: String) = {
    _delegate.checkClientTrusted(chain, authType)
  }

  override def checkServerTrusted(chain: Array[X509Certificate], authType: String) {
    try {
      _delegate.checkServerTrusted(chain, authType)
    } catch {
      case e: Exception =>
        throw e
    }
  }
}


private[sslol] sealed trait KeyStoreableCert {
  def alias: String
  def x509Cert: X509Certificate

  def subject = x509Cert.getSubjectX500Principal
  def issuer = x509Cert.getIssuerX500Principal

  lazy val sha1 = {
    shaDigest.update(x509Cert.getEncoded)

    hexEncode(shaDigest.digest)
  }


  lazy val md5 = {
    md5Digest.update(x509Cert.getEncoded)

    hexEncode(md5Digest.digest)
  }

  def shaSumStartsWith(testString: String): Boolean = {
    val cleanedTestString = testString.toLowerCase.trim.replaceAll(" ", "")

    sha1.startsWith(cleanedTestString)
  }

  def addToKeystore(keyStore: KeyStore) {
    keyStore.setCertificateEntry(alias, x509Cert)
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
      if (keyStore.isCertificateEntry(alias)) {
        val x509Cert = keyStore.getCertificate(alias).asInstanceOf[X509Certificate]
        val maybeLolCert = for (hit <- keystoreAliasRegex.findFirstMatchIn(alias)) yield {
          new SSLOLCert(x509Cert, hit.group("host"), hit.group("port").toInt)
        }

        val cert = maybeLolCert getOrElse new SeriousBusinessCert(x509Cert, alias)

        certs + (alias -> cert)
      } else {
        certs
      }
    }
  }
}

private[sslol] class SeriousBusinessCert(val x509Cert: X509Certificate, val alias: String) extends KeyStoreableCert

private[sslol] class SSLOLCert(val x509Cert: X509Certificate, host: String, port: Int) extends KeyStoreableCert {

  override def alias = {
    "sslol:host=" + host + ":port=" + port
  }

  override def toString = {
    "SSLOLCert(alias=" + alias + ", subject=" + subject + ", issuer=" + issuer + ", sha1=" + sha1 + ", md5=" + md5 + ")"
  }
}

private[sslol] case class HandshakeResponse(certs: Seq[SSLOLCert], val handshakeSucceeded: Boolean)


private[sslol] class SSLOLKeys(val certs: Map[String, KeyStoreableCert] = Map.empty) {
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

  def contains(cert: KeyStoreableCert) = {
    certs contains cert.alias
  }

  def withCert(cert: SSLOLCert): SSLOLKeys = {
    new SSLOLKeys(certs + (cert.alias -> cert))
  }

  def withCerts(certs: Seq[SSLOLCert]): SSLOLKeys = {
    certs.foldLeft(this)((accum, next) => accum.withCert(next))
  }

  def managedCerts: Seq[SSLOLCert] = {
    certs.values.flatMap {
      case lolCert: SSLOLCert => Some(lolCert)
      case _: SeriousBusinessCert => None
    }.toSeq
  }

  def store(file: File, password: String=SSLOL.DEFAULT_PASSWORD) {
    val outStream = new FileOutputStream(file)
    _keyStore.store(outStream, password.toArray)
    outStream.close()
  }

  //
  // Private members
  //
  private lazy val _trustManagers = {
    val defaultTrustAlgo = TrustManagerFactory.getDefaultAlgorithm
    val trustMgrFact = TrustManagerFactory.getInstance(defaultTrustAlgo)
    trustMgrFact.init(_keyStore)

    trustMgrFact.getTrustManagers()
  }

  private lazy val _keyStore: KeyStore = {
    val ks = KeyStore.getInstance(KeyStore.getDefaultType)
    ks.load(null, null)

    certs.foreach { case (alias, cert) =>
      ks.setCertificateEntry(alias, cert.x509Cert)
    }

    ks
  }
}


object SSLOLKeys {
  val empty = new SSLOLKeys()
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
    val customTrustStorePath = Option(System.getProperty("javax.net.ssl.trustStore"))
    val javaHome = System.getProperty("java.home")
    val cacertsDir = javaHome + sep + "lib" + sep + "security"
    val javaDefaultCandidateFiles = List("jssecacerts", "cacerts").map(name => cacertsDir + sep + name)
    val candidateFiles = customTrustStorePath.map(path => path :: javaDefaultCandidateFiles).getOrElse(javaDefaultCandidateFiles)
    val certsFileCandidates = for (filePath <- candidateFiles) yield new File(filePath)
    val maybeCertsFile = certsFileCandidates.find(_.isFile)

    val certsFile = maybeCertsFile.getOrElse {
      throw new RuntimeException(
        "We wants your default cacerts file and can't finds. Find it and put it in one of these places:\n" +
        certsFileCandidates.map(_.getAbsolutePath).mkString(",\n")
      )
    }

    // Get truststore password -- unless we're using a custom truststore it should be SSLOL.DEFAULT_PASSWORD
    val password = Option(System.getProperty("javax.net.ssl.trustStorePassword")).getOrElse(SSLOL.DEFAULT_PASSWORD)

    new SSLOLDB(certsFile, password)
  }

  def apply(cacertsFile: String = "sslolcacerts", password: String = SSLOL.DEFAULT_PASSWORD): SSLOLDB = {
    new SSLOLDB(new File(cacertsFile), password)
  }
}


