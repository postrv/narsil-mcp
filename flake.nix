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
        ] ++ lib.optionals stdenv.isDarwin [
          darwin.apple_sdk.frameworks.Security
          darwin.apple_sdk.frameworks.SystemConfiguration
        ];

      in {
        packages = {
          default = pkgs.rustPlatform.buildRustPackage {
            pname = "narsil-mcp";
            version = "1.4.0";

            src = pkgs.lib.cleanSource ./.;

            cargoLock.lockFile = ./Cargo.lock;

            inherit nativeBuildInputs buildInputs;

            buildFeatures = [ "native" ];

            meta = with pkgs.lib; {
              description = "MCP server for code intelligence";
              homepage = "https://github.com/postrv/narsil-mcp";
              license = licenses.mit;
              maintainers = [ ];
              mainProgram = "narsil-mcp";
            };
          };

          with-frontend = pkgs.rustPlatform.buildRustPackage {
            pname = "narsil-mcp";
            version = "1.4.0";

            src = pkgs.lib.cleanSource ./.;

            cargoLock.lockFile = ./Cargo.lock;

            inherit nativeBuildInputs buildInputs;

            buildFeatures = [ "native" "frontend" ];

            meta = with pkgs.lib; {
              description = "MCP server for code intelligence (with web frontend)";
              homepage = "https://github.com/postrv/narsil-mcp";
              license = licenses.mit;
              mainProgram = "narsil-mcp";
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
          ];

          RUST_SRC_PATH = "${pkgs.rust.packages.stable.rustPlatform.rustLibSrc}";
        };
      });
}
