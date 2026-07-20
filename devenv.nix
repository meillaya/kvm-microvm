# devenv.nix — kvm-microvm-orchestrator
# Cross-platform baseline + Linux-only KVM/QEMU/nft tooling + Rust toolchain pins.
# NOTE: there is NO KVM/QEMU daemon module in devenv 2.x — those would error at
# evaluation. The orchestrator manages the VM host stack through its own
# host-side scripts and Rust crates, not devenv-managed services.
{ pkgs
, lib
, ...
}:

lib.mkMerge [
  # ----- Cross-platform base: editor / shell niceties + git-hooks config -----
  {
    # git-hooks input declared in devenv.yaml; we keep pre-commit narrow so
    # Rust-specific linters are added in task 2 (workspace scaffold).
    git-hooks.hooks = {
      nixpkgs-fmt.enable = true;
      deadnix.enable = true;
      trim-trailing-whitespace.enable = true;
      end-of-file-fixer.enable = true;
      check-yaml.enable = true;
      check-merge-conflicts.enable = true;
    };

    # Generic dev tools that are useful on every platform (macOS dev, Linux CI, etc.).
    packages = with pkgs; [
      git
      gnumake
      gnused
      gnugrep
      coreutils
      jq
      just
      nixfmt-rfc-style
    ];

    # env vars for downstream Rust tooling (loaded when devenv shell starts).
    env = {
      # Rust will land its own rust-toolchain.toml in task 2; here we just keep
      # sane defaults so `devenv shell` does not pollute the env.
      RUST_BACKTRACE = "1";
      CARGO_TERM_COLOR = "always";
    };
  }

  # ----- Linux-only branch: KVM/QEMU/nft + Rust toolchain pins -----
  (lib.mkIf pkgs.stdenv.isLinux {
    packages = with pkgs; [
      # VM hosting stack — used by orchestrator + dev loops on Linux.
      qemu_kvm # /usr/bin/qemu-system-x86_64 with KVM accelerator
      nftables # nft CLI for tenant network policy
      cpio # initrd assembly for microvm guest payloads
      util-linux # nsenter, unshare, lscpu, lsblk — host introspection
      kmod # modprobe/lsmod for kvm_intel / kvm_amd / tun
      e2fsprogs # mkfs.ext4 for guest rootfs
      qemu # fallback plain qemu when KVM is unavailable
      pciutils # lspci for /dev/kvm host topology
      which # locate firecracker/jailer in PATH inside scripts
      docker # Docker CLI + daemon for benchmark comparison

      # Official Firecracker v1.16.1 static musl release (not the nixpkgs
      # glibc build, which is dynamically linked and fails the binary
      # provenance gate requiring static/musl ELF).
      (pkgs.stdenv.mkDerivation {
        pname = "firecracker-release";
        version = "1.16.1";
        src = pkgs.fetchurl {
          url = "https://github.com/firecracker-microvm/firecracker/releases/download/v1.16.1/firecracker-v1.16.1-x86_64.tgz";
          sha256 = "sha256-OCoCqGnk1tXLFMQFd/lUXoRYAh6osLLT/BDsFNnCQuY=";
        };
        dontUnpack = true;
        dontFixup = true;
        nativeBuildInputs = [ pkgs.gnutar pkgs.gzip ];
        installPhase = ''
          mkdir -p $out/bin
          tar xzf $src -C $out/bin --strip-components=1 --wildcards '*/firecracker-*' '*/jailer-*'
          mv $out/bin/firecracker-v1.16.1-x86_64 $out/bin/firecracker
          mv $out/bin/jailer-v1.16.1-x86_64 $out/bin/jailer
          chmod +x $out/bin/firecracker $out/bin/jailer
        '';
      })
    ];

    # Rust toolchain pinned to the version the workspace will adopt in task 2.
    # Declaring rustup + the channel here keeps `devenv shell -- rustc --version`
    # reproducible across hosts even when no system Rust is installed.
    languages.rust = {
      enable = true;
      channel = "stable";
      components = [
        "rustc"
        "cargo"
        "rustfmt"
        "clippy"
        "rust-analyzer"
        "rust-src"
      ];
      targets = [ "x86_64-unknown-linux-gnu" ];
    };

    # VM-daemon devenv modules intentionally NOT declared — they do not exist
    # in devenv 2.x. Host orchestration is owned by the Rust crates built in
    # tasks 5+ and the preflight script from task 4.

    env = {
      # Make KVM/nft tooling discoverable by downstream scripts without
      # hardcoding /nix/store paths.
      LINUX_DEVENV = "1";
    };
  })
]
