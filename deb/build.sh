#!/bin/sh

die () {
    >&2 echo "$1"
    exit 1
}


(
    rm -rf package || die "Failed to remove old packages"
)

(
    cd ../
    make -j "$(nproc)" || die "Failed to build project"
    make DESTDIR="deb/package/" install || die "Failed to install project into package directory"
)

mkdir -p package/DEBIAN/
VERSION="$(head -n 1 ../README | sed -E "s/^pcapfix v([[:digit:]]+.[[:digit:]]+.[[:digit:]]+) README$/\1/")"
cp control.template package/DEBIAN/control
sed "s/%VERSION%/$VERSION/" -i package/DEBIAN/control
sed "s/%ARCHITECTURE%/$(dpkg --print-architecture)/" -i package/DEBIAN/control

mkdir -p package/usr/share/doc/pcapfix/
cp copyright package/usr/share/doc/pcapfix/copyright

echo "Building package..."
dpkg-deb --root-owner-group --build package pcapfix.deb || die "Failed to build package"

echo "Package $(dpkg-deb --show pcapfix.deb | sed "s/\t/ /") successful builded!"
