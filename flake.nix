{
  description = "MCP server for code intelligence with 79 tools across 32 languages";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};

        nativeBuildInputs = with pkgs; [
          pkg-config
          rustPlatform.bindgenHook
        ];

        buildInputs = with pkgs; [
          openssl
          zstd
        ];

        # Integration tests expect external tools (notably git) and a writable HOME.
        # In Nix builds, those are not available unless explicitly provided.
        nativeCheckInputs = with pkgs; [
          git
          coreutils
        ];

        common = { buildFeatures, meta ? { } }:
          pkgs.rustPlatform.buildRustPackage {
            pname = "narsil-mcp";
            version = "1.4.0";

            src = pkgs.lib.cleanSource ./.;

            cargoLock.lockFile = ./Cargo.lock;

            inherit nativeBuildInputs buildInputs nativeCheckInputs;

            inherit buildFeatures;

            # Many integration tests create temp repos and need a writable HOME.
            preCheck = ''
              export HOME="$(mktemp -d)"
            '';

            meta = (with pkgs.lib; {
              description = "MCP server for code intelligence";
              homepage = "https://github.com/postrv/narsil-mcp";
              license = licenses.mit;
              maintainers = [ ];
              mainProgram = "narsil-mcp";
              platforms = platforms.all;
            }) // meta;
          };
      in
      {
        packages = {
          default = common {
            buildFeatures = [ "native" ];
          };

          with-frontend = common {
            buildFeatures = [ "native" "frontend" ];
            meta = {
              description = "MCP server for code intelligence (with web frontend)";
            };
          };
        };

        apps.default = {
          type = "app";
          program = "${self.packages.${system}.default}/bin/narsil-mcp";
        };

        devShells.default = pkgs.mkShell {
          inputsFrom = [ self.packages.${system}.default ];
          packages = with pkgs; [
            cargo
            rustc
            rust-analyzer
            clippy
            rustfmt
            git
          ];

          RUST_SRC_PATH = "${pkgs.rust.packages.stable.rustPlatform.rustLibSrc}";
        };
      });
}
