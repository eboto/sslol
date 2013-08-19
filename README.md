# SSLOL: "Proceed Anyways" for Scala web requests

We've all at some point gone **too deep into the internet**. You know what I mean... *this deep* .

![Proceed anyways](sslol_graphic.png)

Then what do we do? We either **run away**, or **proceed anyways**.

The problem is, our scala software doesn't have the same choice. The JVM doesn't allow us to easily
*proceed anyways* without using the terrible `keytool`.

This library allows you to *proceed anyways* from scala without screwing around with `keytool`.

## Getting started

**Get it into your project**
```bash
# Haha what's dependency management? Just blindly execute this foreign code
# and follow the directions. BTW linux and mac only. Sorry guys.
python -c "`curl https://raw.github.com/eboto/sslol/master/get_it.py`"
```

**Use it safely**
```scala
// Somewhere in your application
...
import sslol.{SSLOL, Site}
...
SSLOL.initialize() // This needs to happen before your app's first web request because shenanigans.
...
  def makeSafeRequests = {
    // There is only one "safe" way to use SSLOL. Accept any certificate whose SHA1 hash begins
    // with a particular, known, string (which you should _just know_ from examining the cert in your 
    // browser or file system)
    SSLOL trust Site("evil.com", certShaStartsWith="a1dff43") inPlayground {
      // Any SSL connection you make while in this playground will accept
      // the cert from evil.com, as long as the SHA of its contents started with a1dff43
    }
  }
```

**Other, less safe ways to use it**
```scala
// Somewhere in your application
...
import sslol.{SSLOL, Site}
...
  def makeUnsafeRequests = {
    // Want to live life on the edge? Accept any old certificate you get. This is the
    // format you'll see in the examples because it's short and dangerous like Joe Pesci,
    // but for God's sake don't use it.
    SSLOL trust "evil.com" inPlayground { /* HIC SVNT DRACONIS */ }

    // You can trust a couple sites at a time...
    SSLOL trust "evil.com" trust "veryevil.com" trust "superevil.com" inPlayground {
      // Why, why, why are you doing this?
    }

    // Specify a port if you want (it's 443 by default)...
    SSLOL trust Site("evil.com", port=89) inPlayground { /* things go here */}

    // Want async? that's cool. The playground will clean up immediately after the Future
    // is realized. Don't get too fancy with this -- under the hood we're manipulating singleton
    // state in the JVM's SSL implementation.
    val futureResult: Future[Int] = SSLOL trust "evil.com" inPlayground { getSinCountFromEvilDotCom() }

    // Or enable SSLOL statefully, to control the playground's lifecycle in a larger application
    val ssl = SSLOL trust "evil.com"
    ssl.openPlayground()
    // Be careful to close the playground, or the untrust-store will leak to the rest
    // of your JVM!
    ssl.closePlayground()

    // Store a custom untrust store to disk
    SSLOL trust "evil.com" store "evil.jks" // You could also provide a password if you want but who cares lol

    // Load the untrust store and do bad things
    SSLOL load "evil.jks" inPlayground { /* shenanigans */ }
  }
}
```

# Main features

  * Make web requests over SSL with sites whose certs are not signed by known
    Certificate authorities.

  * Store these custom untrust-stores for later use in shooting yourself in
    the foot: `SSLOL trust "evil.com" store "evil.jks"`

  * Is not `keytool`

  * Is one unmaintainable mess of a file.

  * Has jokes


## Frequently Asked Questions

**What do you use SSLOL for?**

  * I use it to make requests against internal services that use self-signed certs (Confluence, I'm looking at you!)

  * I use it to write integration tests against locally hosted apps over https despite
    that they don't yet have CA-signed certs.

  * I use it to create custom certificate truststores.
    *  `SSLOL trust "mywiki.com" trust "myjira.com" store "internal_sites.jks"`

  * I use it to make terrible, life-altering mistakes.

**I already use a custom KeyStore / TrustStore. Will SSLOL work?**

Any private keys in your custom KeyStore will be broken in the SSLOL playground, along with your sense
of professional responsibility.

If you have a custom KeyStore that contains nothing but certs, then include it in SSLOL like this:
`SSLOL load "path/to/my/keystore.jks" trust "evil.com" inPlayground { /* nothin' but trouble */ }`

**How do you suggest using SSLOL?**

*I do not suggest using SSLOL*

**What is this library missing?**

Besides a conscience, SSLOL still needs:

  * **Support for hot-reloading**. Mucking around with the JVM-default SSLContext doesn't seem to
    work in a hot-reload scenario. Meaning, the tests only pass because they are configured to execute
    on a forked jvm.
  * **To get rid of the stupid SSLOL.initialize method**. I hate that it's necessary, but otherwise
    any web-request library you use before your first SSLOL call will forever store the useless
    default SSLContext. Any ideas?
  * **Thread safety**. Outcomes are undetermined if you're creating a bunch of different playgrounds
    because under the hood we're just shimming out a var that represents the set of trusted sites.
    However, if you created an actor that linearized update of trusted sites then the library could
    be much more predictable. The good news is that most apps won't need more than one playground.

**Wait a second, how safe is this library?**

This library is about as safe as unprotected sex.

**So why did you build it?**

Because I am not a smart man.
