# PGPChatApp

## Introduction
This project demonstrates a command-line group chat interface, and features both cryptographic and compression techniques. 

## Running the Program
**_A Note on Debugging:_** This program makes use of configurable debugging output to demonstrate the flow of the program. Toggling this is achieved by the `<debug mode>` command-line argument. When this is set to `1`, expect to see detailed debugging output. For an uninterrupted experience, set `0` as this parameter.

**_A Note on ports and hostnames_**: To enable successful connection, clients and the server must set the same port number. This can be any four digit, valid port configuration. Clients should select a common host-name. To run the program on your own network, selecting `localhost` for this parameter is advisable.

**_A Note on the external libraries_**: When compiling and executing, an additional `cp` parameter is required due to the use of the Bouncy Castle library. The required external libraries are included within the `extlibs` folder.

**_A Note on the AsymmetricUtility unit tests_**: To run the unit tests for AsymmetricUtility, please remove the "BC" in the `getInstance()` method in the  `AssymetricUtility.java` class when you generate the keys.

### Compilation
In the directory with the java files do the following:
To compile all java files:
```
[Windows] javac -cp '.\extlibs\*' .\*.java
[Linux] javac -cp './extlibs/*' ./*.java
```

### The Server
Please run the code with the following parameters:
```
[Windows] java -cp '.:.\extlibs\*' Server <port> <debug mode>
[Linux] java -cp '.:./:extlibs/*' Server <port> <debug mode>
```

### The Client
Please run the code with the following parameters:
```
[Windows] java -cp '.:.\extlibs\*' Client <port> <hostname> <debug mode>
[Linux] java -cp '.:./:extlibs/*' Client <port> <hostname> <debug mode>

```

#### Quick Config
This configuration is supplied to enable easy copying and pasting as you prepare to execute this chat program with debugging output.
```
[Windows]
javac -cp '.\extlibs\*' .\*.java

java -cp '.:.\extlibs\*;' Server 8080 1

java -cp '.:.\extlibs\*;' Client 8080 localhost 1

[Linux]
javac -cp './extlibs/*' ./*.java

java -cp '.:./:extlibs/*' Server 8080 1

java -cp '.:./:extlibs/*' Client 8080 localhost 1
```
