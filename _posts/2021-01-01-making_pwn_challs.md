---
layout: post
title: Making pwn challenges
categories: Pwn
---



This is a collection of tips and tricks I have discovered in my working for FHICTF.

## External sources

<https://github.com/pwning/docs/blob/master/suggestions-for-running-a-ctf.markdown>

## Buffers

The "Suggestions for running a ctf" by PPP suggested using either xinetd or fork/accept in the binary itself for running remote challenges. When I joined FHICTF, there was one example pwn challenge, which used socat in docker. Because this seemed to work fine, I have not yet looked into the differences and possible problems with our approach.

One issue we have had was that when doing the challenge, netcat would not receive any data until the connection closed. Then it would suddenly flood the terminal.

This is what we used in the dockerfile:

```Dockerfile
ENTRYPOINT socat TCP-LISTEN:8080,reuseaddr,fork EXEC:"./challenge_format"
```

The solution I found was to use a setvbuf in main().

```C
int main()
{
    setvbuf(stdout, NULL, _IONBF, 0);
    vuln();
    puts("Exiting!\n");
    return 0;
}
```

## Makefile and GCC flags

To keep the binaries consistent, and to avoid issues with 32 bits vs 64 bits libraries, we build the challenges inside of docker.

For rev challs, consider running `strip $(TARGET)` after GCC.

TODO: explain all relevant flags

```make
TARGET=challenge_format

INCLUDEFLAGS=-Isrc -Iinclude -Iinclude/interfaces 
CXXFLAGS= $(INCLUDEFLAGS) -m32
CXX=gcc
INSECUREFLAGS=-fno-stack-protector -no-pie
DEBUGFLAGS=-ggdb -g -O0

SOURCES=$(wildcard *.c)
HEADERS=$(wildcard *.h)

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SOURCES) $(HEADERS) Makefile
    @$(CXX) $(CXXFLAGS) $(DEBUGFLAGS) $(INSECUREFLAGS) -o $@ $(SOURCES)

clean:
    @rm $(TARGET)
```

## Docker commands

```bash
sudo docker build -t challenge_name .
sudo docker run challenge_name -p 8080:8080
sudo docker stop $(sudo docker ps -a -q) && sudo docker rm $(sudo docker ps -a -q)
sudo docker cp sad_brattain:/home/user/challenge_name .
nc 172.17.0.2 8080
```

TODO:

-z execstack

these days most challs are 64 bit

<https://www.youtube.com/watch?v=VCwiZ2dh17Q&list=PLhixgUqwRTjzTvVyL_8H-DJBf8VT3uiu2&index=2>
