========
jaramiko
========

:Jaramiko: Java SSH Library
:Copyright: Copyright (c) 2005-2007  Robey Pointer <robey@lag.net>
:License: MIT
:Homepage: http://www.lag.net/jaramiko/


NOTICE:
=======

While starting to organize this repository and look for features which need to
be implemented I stumbled upon the JSch library: http://www.jcraft.com/jsch/.
My intentions for this library was to use it for Jython as a drop in
replacement for paramiko. However, I realized that even if I wrapped JSch or
implemented methods to make jaramiko a "drop in" replacement for paramiko it
would never be truly a drop in replacement because I would still need to handle
the Java-Python differences in a Python wrapper (a smaller one, but it would
still have to be created and maintained). With this in mind I have decided I
would *not* contribute to this repository anymore, but instead suggest you use
the JSch library (It is already being used by Apache Ant and Eclipse amongst
others). Instead, I will likely be working on trying to make a paramiko branch
which is compatible with Jython.


version 2.0beta (May 23, 2011)
==============================
 - forking Robey's code on github
 - cleaning up source files
 - cleaning up build file and straightening build locations
 - moving to java 1.5
 - changing versioning system - all old releases can be considered 1.x where
   x is the old number they were using (Old releases were released by minor
   version)
 - added an sftp patch found on the internet (still pending testing)


What
----

Jaramiko is a java port of paramiko, an SSH library for python. It's released
under the MIT license, which basically means you can do what you want with it,
but you can't take credit for it.

Java and python have different attitudes and styles, so the port is not always
literal [*]_. In many cases, the API was changed in jaramiko to make it fit
more with java's style. (For example, derivatives of InputStream and
OutputStream are used instead of fake file descriptors.)

.. [*] This is likely going to change: Public API is not going to be broken
   other than the restriction due to using typed generics which have already
   been committed, but making jaramiko a drop in replacement for paramiko on
   Jython would be a great thing for the adoption of Jython (and the use of
   fabric and boto + other libraries which utilize paramiko on Jython)


Requirements
------------

  - Java 1.5+
  - a JCE implementation, or some sort of basic crypto library

Jaramiko uses an abstracted interface to access crypto functionality, so you
can substitute your own crypto library by writing a glue class. The crypto
interface is called CRAI and lives in package ``net.lag.crai``.


Building and Installing
-----------------------

To compile jaramiko, you only need to do::

    $ ant build

which will build the libraries in ``bin/classes``. There are some extensive
unit tests, which you can run with::

    $ ant test

To build the jar run::

    $ ant jar

which will create the jar: ``dist/jaramiko-${VERSION}.jar``. Adding this jar to
your applications' class path should suffice because there are no other
dependencies.


Usage
-----

There are extensive javadocs, which can be built with::

    $ ant doc

A good place to start is the ``Transport`` class, which handles the actual
SSH connection to a remote host.

There's a small demo included in the ``demo/`` folder, which will connect to a
server, authenticate, execute a shell command or sftp a file, and display the
output. It prompts you for the info it needs. You can build and run it with::

    $ ant demo
