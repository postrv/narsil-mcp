{
  description = "MCP server for code intelligence with 90 tools across 32 languages";

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

        mkPkg = { buildFeatures, withFrontend ? false, checksEnabled ? true }:
          pkgs.rustPlatform.buildRustPackage {
            pname = "narsil-mcp";
            version = "1.5.0";

            src = pkgs.lib.cleanSource ./.;

            cargoLock.lockFile = ./Cargo.lock;

            inherit nativeBuildInputs buildInputs;

            buildFeatures = buildFeatures
              ++ pkgs.lib.optionals withFrontend [ "frontend" ];

            doCheck = checksEnabled;
            cargoTestFlags = pkgs.lib.optionals checksEnabled [ "--lib" ];

            meta = with pkgs.lib; {
              description = "MCP server for code intelligence";
              homepage = "https://github.com/postrv/narsil-mcp";
              license = licenses.mit;
              maintainers = [ ];
              mainProgram = "narsil-mcp";
            };
          };

      in {
        packages = {
          default = mkPkg {
            buildFeatures = [ "native" ];
          };

          with-frontend = mkPkg {
            buildFeatures = [ "native" ];
            withFrontend = true;
          };

          no-check = mkPkg {
            buildFeatures = [ "native" ];
            checksEnabled = false;
          };

          with-frontend-no-check = mkPkg {
            buildFeatures = [ "native" ];
            withFrontend = true;
            checksEnabled = false;
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
