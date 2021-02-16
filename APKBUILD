# Contributor: Ali Mosajjal <hi@n0p.me>
# Maintainer: Ali Mosajjal <hi@n0p.me>
pkgname=arkime
pkgver=2.7.1
pkgrel=0
pkgdesc="Arkime is a full packet capture engine"
url="https://arkime.com/"
arch="x86_64"
license="Apache-2.0"
makedepends="npm python2 perl-libwww perl-json perl-socket6 perl-test-differences yara wget curl glib-static glib-dev libmaxminddb-static libpcap-dev curl-static nghttp2-static lua5.3-dev daq-static openssl-libs-static libmaxminddb-dev yaml-dev libmagic file-dev curl-dev autoconf alpine-sdk automake"
source="$pkgname-$pkgver.zip::https://github.com/arkime/arkime/archive/v${pkgver}.zip"
builddir="$srcdir/$pkgname-${pkgver}"


build() {
	./bootstrap.sh
    ./configure --with-libpcap=/usr --with-yara=/usr --with-maxminddb=yes LDFLAGS="-L/usr/local/lib" --with-glib2=yes GLIB2_CFLAGS="-I/usr/lib -I/usr/lib/glib-2.0/include -I/usr/include/glib-2.0 -I/usr/include/openssl/" GLIB2_LIBS="-L/usr/lib -lglib-2.0 -lmaxminddb -lgmodule-2.0 -lgobject-2.0 -lgio-2.0" --with-pfring=no --with-curl=yes --with-nghttp2=yes --with-lua=no LUA_CFLAGS="-I/usr/lib" LUA_LIBS="-L/usr/lib -llua"
    make -j16
}

check() {
	make check
}

package() {
	make DESTDIR="$pkgdir" install
}

sha512sums="156eb26a6dffd607417e22e690ada4e1ca655e32fbae72cb4d395378081555d9421eb0829facd430d9482d55d88c0a603aed800439546544e9b8de55bdd4923e  arkime-2.7.1.zip"
