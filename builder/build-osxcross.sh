if [ -e "/System" ]; then
    echo "/osxcross already build. Skipping the build process..."
    exit 0
fi
cd /build/osxcross
TP_OSXCROSS_DEV=/build SDK_VERSION=11.3 UNATTENDED=yes OSX_VERSION_MIN=10.13 ./build.sh
ln -s /build/osxcross/target/SDK/MacOSX11.3.sdk/System/ /System
