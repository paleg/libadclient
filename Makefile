libadclient:
	g++ -o adclient.os -c -O0 -g -Wall -fPIC -I. -I/usr/local/include -I/usr/include adclient.cpp
	g++ -o libadclient.so -shared adclient.os -L/usr/lib -L/usr/local/lib -L/lib -lldap -lstdc++
clean:
	rm -f libadclient.so adclient.os
install: libadclient
	#install -v -s libadclient.so /usr/local/lib/
	cp -v libadclient.so /usr/local/lib/
uninstall:
	rm -fv /usr/local/lib/libadclient.so
package: clean
	rm -f ../libadclient-unix.tar.bz2 && cd ../ && tar --exclude=build --exclude=config.log --exclude=*scon* --exclude=Makefile --exclude=.svn --exclude=temp -cvjf libadclient-unix.tar.bz2 libadclient-unix
