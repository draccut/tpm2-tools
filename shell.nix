{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  buildInputs = with pkgs; [
    # Build-Tools
    autoconf
    automake
    libtool
    autoconf-archive
    pkg-config
    gnumake
    gcc
    pandoc

    # TPM-Stack
    tpm2-tss
    tpm2-abrmd
    swtpm

    # Libraries
    openssl
    curl
    cmocka
    dbus

    # Tests
    python3
    python3Packages.pyyaml
    expect
  ];

  shellHook = ''
    echo "---------------------------------------------------"
    echo "  ./bootstrap && ./configure && make -j\$(nproc)"
    echo "  make"
    echo "---------------------------------------------------"
    export PATH="${pkgs.tpm2-abrmd}/bin:${pkgs.swtpm}/bin:$PATH"
  '';
}
