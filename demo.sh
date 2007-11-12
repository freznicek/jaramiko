#!/bin/sh
if [ "x$JAVA_HOME" = "x" ]; then
    java="java"
else
    java="$JAVA_HOME/bin/java"
fi

${java} -classpath demo-classes:jaramiko.jar net.lag.jaramiko.demos.SimpleDemo

