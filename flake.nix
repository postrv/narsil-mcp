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

        # Build the React frontend as a separate derivation.
        # Only evaluated when withFrontend = true.
        frontendDist = pkgs.buildNpmPackage {
          pname = "narsil-mcp-frontend";
          version = "1.6.0";
          src = ./frontend;
          npmDepsHash = "sha256-zwO2ek9o4QMJ9jeTzPVGZzgG46NEpHEnpE5OMiXXixQ=";
          # The build script is "tsc -b && vite build"
          buildPhase = ''
            npm run build
          '';
          installPhase = ''
            cp -r dist $out
          '';
        };

        mkPkg = { buildFeatures, withFrontend ? false, checksEnabled ? true }:
          pkgs.rustPlatform.buildRustPackage {
            pname = "narsil-mcp";
            version = "1.6.0";

            src = pkgs.lib.cleanSource ./.;

            cargoLock.lockFile = ./Cargo.lock;

            inherit nativeBuildInputs buildInputs;

            # When building with frontend, copy the pre-built dist into the source
            # tree before Cargo runs, so rust_embed's #[folder = "frontend/dist"]
            # can find it.
            preBuild = pkgs.lib.optionalString withFrontend ''
              mkdir -p frontend/dist
              cp -r ${frontendDist}/* frontend/dist/
            '';

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
            nodejs  # For frontend development
          ];

          RUST_SRC_PATH = "${pkgs.rust.packages.stable.rustPlatform.rustLibSrc}";
        };
      });
}
