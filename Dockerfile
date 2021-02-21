FROM alpine:3.13

ENV VER="2.7.1"

RUN apk add yara --repository http://dl-3.alpinelinux.org/alpine/edge/testing/
RUN apk add npm wget curl glib-static glib-dev libmaxminddb-static libpcap-dev curl-static nghttp2-static lua5.3-dev daq-static openssl-libs-static libmaxminddb-dev yaml-dev libmagic file-dev curl-dev autoconf alpine-sdk automake

RUN ln -s /usr/bin/python3 /usr/bin/python

RUN cd /root/ && wget https://github.com/arkime/arkime/archive/v$VER.zip && unzip v$VER.zip

WORKDIR /root/arkime-$VER

RUN ./bootstrap.sh
RUN ./configure --with-libpcap=/usr --with-yara=/usr --with-maxminddb=yes LDFLAGS="-L/usr/local/lib" --with-glib2=no GLIB2_CFLAGS="-I/usr/lib -I/usr/lib/glib-2.0/include -I/usr/include/glib-2.0 -I/usr/include/openssl/" GLIB2_LIBS="-L/usr/lib -lglib-2.0 -lmaxminddb -lgmodule-2.0 -lgobject-2.0 -lgio-2.0" --with-pfring=no --with-curl=yes --with-nghttp2=yes --with-lua=no LUA_CFLAGS="-I/usr/lib" LUA_LIBS="-L/usr/lib -llua"

RUN mkdir -p /data/moloch && make -j16 && make install

FROM alpine:3.13
RUN mkdir -p /data/moloch
COPY --from=0 /data/moloch/ /data/moloch/
RUN apk add libmaxminddb libmagic libuuid libpcap glib libcurl lua5.3 nghttp2 npm yaml bash ethtool jq perl perl-libwww perl-json
RUN ln -s /usr/sbin/ethtool /sbin/ethtool

COPY entrypoint.sh /data/moloch/

ENV ES_HOST=http://elasticsearch:9200 \
	INTERFACE=eth0 \
	CLUSTER_PW=secretpw \
	ADMIN_PW=supersecretpw \
	SENSOR=true

RUN chmod +x /data/moloch/*.sh && \
	chmod +x /data/moloch/db/db.pl /data/moloch/*/*.sh && \
	cd /data/moloch/viewer && \
	ln -s /usr/bin/node /data/moloch/bin/node  && \
	npm update . && \
	npm install .

ADD config.ini /data/moloch/etc/config.ini
RUN chmod 755 /data/moloch/etc/config.ini

EXPOSE 8005

WORKDIR /data/moloch

ENTRYPOINT ["./entrypoint.sh"]
# ENTRYPOINT ["/bin/sh"]