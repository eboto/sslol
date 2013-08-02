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

// This is the only stupid underscore import I should ever see in this file.
import collection.JavaConversions._


//
// Public Types
//
object SSLOL extends SSLolling {
  lazy val lolKeys = SSLOLDB().getKeys
  override def seriousKeys = SSLOLDB.jreDefault.getKeys

  def load(file: String, password: String = ""): SSLolling = {
    new SSLOL(SSLOLDB(file, password).getKeys)
  }
}

/**
 * The main type in this library and the source of your company's
 * next security breach. You never need to instantiate it, just call it by
 * its companion that I strangely also made have most of its functionality.
 */
class SSLOL(protected val lolKeys: SSLOLKeys) extends SSLolling {
  override def seriousKeys = SSLOL.seriousKeys
}

/**
 * Use this to specify what sites you want to trust. Only really need it
 * if you've got an alternate port, or want to be safer and specify a sha hash
 * for the cert we're gonna trust.
 */
case class Site(host: String, port:Int=443, certShaStartsWith: String="") {
  def sha = certShaStartsWith
}


//
// Private-ish types that you really shouldn't use, but can if you need to
// mock SSLOL.
//
trait SSLolling {
  protected def lolKeys: SSLOLKeys
  protected def seriousKeys: SSLOLKeys

  private lazy val allKeys = seriousKeys adding lolKeys

  private var origSslContext: Option[SSLContext] = None

  def trust(host: String): SSLolling = {
    trust(Site(host))
  }

  def trust(site: Site): SSLolling = {
    val response = gimmeCertsOf(site)
    val certChainContainsSha = response.certs.find(_.shaSumStartsWith(site.sha)).isDefined

    if (!response.certsWereAccepted && certChainContainsSha) {
      new SSLOL(lolKeys.withCerts(response.certs))
    } else {
      // Either we already trusted the cert chain, or the cert chain returned to us
      // didn't contain a cert with the desired sha so even _we_ can't trust it
      this
    }
  }

  def openPlayground() {
    origSslContext = Some(SSLContext.getDefault)
    SSLContext.setDefault(allKeys.sslContext)
  }

  def closePlayground() {
    origSslContext.map(SSLContext.setDefault(_))
  }

  def inPlayground[T](operation: => Future[T])(implicit ec: ExecutionContext): Future[T] = {
    val futureResult = inPlayground(operation)

    futureResult.onComplete(result => closePlayground())

    futureResult
  }

  def inPlayground[T](operation: => T): T = {
    openPlayground()

    try {
      operation
    } finally {
      closePlayground()
    }
  }

  def gimmeCertsOf(site: Site) = {
    // Initialize the memoing trustmanager that will record certificates passed in
    // for validation.
    val x509TrustMgr = allKeys.trustManager
    val memo = new MemoingTrustManager(x509TrustMgr)

    // Initialize an SSL context with our memoing trust manager and make the request.
    val sslContext = SSLContext.getInstance("TLS")
    sslContext.init(null, Array(memo), new SecureRandom)

    val canHazHandshake = _iCanHazHandshake(site.host, site.port, sslContext)
    val certs = memo.certChain.map(x509Cert => new SSLOLCert(x509Cert, site.host, site.port))

    new SSLOLCertResponse(certs, canHazHandshake)
  }

  def managedCerts: Seq[X509Certificate] = {
    lolKeys.managedCerts
  }

  def withPassword(pass: String) = {
    new SSLOL(lolKeys.withPassword(pass))
  }

  def store(file: File): SSLolling = {
    lolKeys.store(file)

    this
  }

  def store(filename: String): SSLolling = {
    lolKeys.store(new File(filename))

    this
  }

  //
  // Private members
  //
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


private[sslol] class SSLOLCert(cert: X509Certificate, host: String, port: Int) {
  val List(shaDigest, md5Digest) = List("sha1", "md5").map(MessageDigest.getInstance)

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

  def alias = {
    "sslol-" + host + ":" + port + "(sha=" + sha1 + ")"
  }

  def addToKeystore(keyStore: KeyStore) {
    keyStore.setCertificateEntry(alias, cert)
  }

  override def toString = {
    "SSLOLCert(alias=" + alias + ", subject=" + subject + ", issuer=" + issuer + ", sha1=" + sha1 + ", md5=" + md5 + ")"
  }

  private def hexEncode(toEncode: Array[Byte]) = {
    toEncode.map(Byte.box).map(byte => String.format("%x", byte)).mkString
  }
}


private[sslol] case class SSLOLCertResponse(certs: Seq[SSLOLCert], val certsWereAccepted: Boolean)


private[sslol] class SSLOLKeys(val keyStore: KeyStore, password: String) {
  lazy val trustManager = {
    _trustManagers(0).asInstanceOf[X509TrustManager]
  }

  lazy val sslContext = {
    val context = SSLContext.getInstance("TLS")
    context.init(null, _trustManagers, null)

    context
  }

  def adding(other: SSLOLKeys): SSLOLKeys = {
    val newKeyStore = _copyKeyStore

    _addAllOfKeyStore(source=other.keyStore, target=newKeyStore)

    new SSLOLKeys(newKeyStore, password)
  }

  def withCert(cert: SSLOLCert): SSLOLKeys = {
    val newKs = _copyKeyStore
    cert.addToKeystore(newKs)
    _copy(keyStore=newKs)
  }

  def withCerts(certs: Seq[SSLOLCert]): SSLOLKeys = {
    certs.foldLeft(this)((accum, next) => accum.withCert(next))
  }

  def managedCerts: Seq[X509Certificate] = {
    val managedAliases = keyStore.aliases.filter(_.startsWith("sslol")).toSeq

    managedAliases.map(alias => keyStore.getCertificate(alias).asInstanceOf[X509Certificate])
  }

  def withPassword(newPassword: String): SSLOLKeys = {
    _copy(password=newPassword)
  }

  def store(file: File) {
    val outStream = new FileOutputStream(file)
    keyStore.store(outStream, password.toArray)
    outStream.close()
  }

  //
  // Private members
  //
  private def _copy(keyStore: KeyStore = this.keyStore, password: String = this.password): SSLOLKeys = {
    new SSLOLKeys(keyStore, password)
  }

  private lazy val _trustManagers = {
    val defaultTrustAlgo = TrustManagerFactory.getDefaultAlgorithm
    val trustMgrFact = TrustManagerFactory.getInstance(defaultTrustAlgo)
    trustMgrFact.init(keyStore)

    trustMgrFact.getTrustManagers()
  }

  private def _addAllOfKeyStore(source: KeyStore, target: KeyStore) {
    source.aliases.map(alias => (alias, keyStore.getCertificate(alias))).foreach { case (alias, cert) =>
      target.setCertificateEntry(alias, cert)
    }
  }
  private def _copyKeyStore: KeyStore = {
    val newKs = KeyStore.getInstance(KeyStore.getDefaultType)
    newKs.load(null, password.toArray)

    _addAllOfKeyStore(source=keyStore, target=newKs)

    newKs
  }
}

class SSLOLDB(file: File, password: String="") {
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

    new SSLOLKeys(keyStore, password)
  }
}

object SSLOLDB {
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
        "Where's your god-damned cacerts file? We looked in these places:\n" +
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