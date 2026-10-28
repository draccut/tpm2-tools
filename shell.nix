{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  buildInputs = with pkgs; [
    tpm2-tools
    tpm2-tss
    pkg-config
    autoconf
    automake
    libtool
    autoconf-archive
    openssl
    curl
    gnumake
    gcc
    cmocka
  ];

  shellHook = ''
    echo "-----------------------------------------------------------------------"
    echo " 1. Build-System vorbereiten:"
    echo "    ./bootstrap && ./configure --enable-unit && make -j16"
    echo ""
    echo " 2. Alle Unit- und Integrationstests ausführen:"
    echo "    make check"
    echo ""
    echo "-----------------------------------------------------------------------"
  '';
}
