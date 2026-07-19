# devenv.nix — kvm-microvm-orchestrator
# Cross-platform baseline + Linux-only KVM/QEMU/nft tooling + Rust toolchain pins.
# NOTE: there is NO KVM/QEMU daemon module in devenv 2.x — those would error at
# evaluation. The orchestrator manages the VM host stack through its own
# host-side scripts and Rust crates, not devenv-managed services.
{
  pkgs,
  lib,
  config,
  ...
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
      qemu_kvm          # /usr/bin/qemu-system-x86_64 with KVM accelerator
      nftables          # nft CLI for tenant network policy
      cpio              # initrd assembly for microvm guest payloads
      util-linux        # nsenter, unshare, lscpu, lsblk — host introspection
      kmod              # modprobe/lsmod for kvm_intel / kvm_amd / tun
      e2fsprogs         # mkfs.ext4 for guest rootfs
      qemu              # fallback plain qemu when KVM is unavailable
      pciutils          # lspci for /dev/kvm host topology
      which             # locate firecracker/jailer in PATH inside scripts
    ];

    # Rust toolchain pinned to the version the workspace will adopt in task 2.
    # Declaring rustup + the channel here keeps `devenv shell -- rustc --version`
    # reproducible across hosts even when no system Rust is installed.
    languages.rust = {
      enable = true;
      channel = "stable";
      toolchain = "1.95.0";
      components = [
        "rustc"
        "cargo"
        "rustfmt"
        "clippy"
        "rust-analyzer"
        "rust-src"
      ];
      # Locked to the system toolchain target triple.
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