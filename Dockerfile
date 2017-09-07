FROM debian:stretch

ENV DEBIAN_FRONTEND noninteractive

RUN apt-get update && \
    apt-get install -y apt-utils && \
    apt-get -y dist-upgrade

RUN apt-get install -y dnsutils scons gcc gdb g++ libldap2-dev libkrb5-dev libsasl2-dev libsasl2-modules-gssapi-mit krb5-user
RUN apt-get install -y python-dev python3 python3-dev
RUN apt-get install -y swig golang git
RUN apt-get install -y valgrind

RUN echo "g++ -ladclient -g -O0 test/test.cpp -o adclient" >> /root/.bash_history
RUN echo "scons install && python setup.py install && python3 setup.py install && ldconfig && g++ -ladclient -g -O0 test/test.cpp -o adclient" >> /root/.bash_history

VOLUME ["/usr/src/libadclient"]
WORKDIR /usr/src/libadclient

ENV GOPATH /root/.go

ENTRYPOINT /bin/bash
