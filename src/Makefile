#Modify this to point to the PJSIP location.
PJBASE=../pjproject-2.7.1

include $(PJBASE)/build.mak

CC      = $(PJ_CC)
LDFLAGS = $(PJ_LDFLAGS)
LDLIBS  = $(PJ_LDLIBS) -lcrypt
CFLAGS  = $(PJ_CFLAGS)
CPPFLAGS= ${CFLAGS}

all: klingel klingel.cgi

klingel: klingel.c config.h
	$(CC) -o $@ $< $(CPPFLAGS) $(LDFLAGS) $(LDLIBS)

klingel.cgi: klingel-cgi.c config.h
	$(CC) -o $@ $< $(CPPFLAGS)

crypt: crypt.c
	$(CC) -o $@ $< $(CPPFLAGS) $(LDFLAGS) $(LDLIBS)

install: klingel klingel.cgi klingel.service klingel.html klingel.json klingel-0-75x.png klingel-1x.png klingel-2x.png klingel-2-6x.png klingel-4x.png klingel-5-3x.png
	-systemctl stop klingel
	cp klingel /usr/local/bin
	cp klingel.cgi /usr/lib/cgi-bin
	cp klingel.service /etc/systemd/system
	cp klingel.html klingel.json klingel-0-75x.png klingel-1x.png klingel-2x.png klingel-2-6x.png klingel-4x.png klingel-5-3x.png /var/www/html
	-systemctl daemon-reload
	-systemctl start klingel

uninstall:
	@rm /usr/local/bin/klingel
	@rm /usr/lib/cgi-bin/klingel.cgi
	@rm /etc/systemd/system/klingel.service
	@rm /var/www/html/klingel.html /var/www/html/klingel.json /var/www/html/klingel-0-75x.png /var/www/html/klingel-1x.png /var/www/html/klingel-2x.png /var/www/html/klingel-2-6x.png /var/www/html/klingel-4x.png /var/www/html/klingel-5-3x.png

clean:
	rm -f klingel.o klingel klingel-cgi.o klingel.cgi crypt.o crypt
