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

        # Keep checks enabled by default.
        # Contributors can set NARSIL_SKIP_CHECKS=1 to skip during packaging installs.
        skipChecks = (builtins.getEnv "NARSIL_SKIP_CHECKS") == "1";

        mkPkg = { buildFeatures, withFrontend ? false, checksEnabled ? true }:
          pkgs.rustPlatform.buildRustPackage {
            pname = "narsil-mcp";
            version = "1.4.0";

            src = pkgs.lib.cleanSource ./.;

            cargoLock.lockFile = ./Cargo.lock;

            inherit nativeBuildInputs buildInputs;

            buildFeatures = buildFeatures;

            # If checks are enabled, provide the basic external tools they typically need.
            nativeCheckInputs = pkgs.lib.optionals checksEnabled (with pkgs; [
              git
              coreutils
            ]);

            preCheck = pkgs.lib.optionalString checksEnabled ''
              export HOME="$(mktemp -d)"
            '';

            # The actual toggle: skip checkPhase when requested.
            doCheck = checksEnabled && (!skipChecks);

            meta = with pkgs.lib; {
              description =
                if withFrontend
                then "MCP server for code intelligence (with web frontend)"
                else "MCP server for code intelligence";
              homepage = "https://github.com/postrv/narsil-mcp";
              license = licenses.mit;
              maintainers = [ ];
              mainProgram = "narsil-mcp";
            };
          };

      in {
        packages = {
          # Default behaviour unchanged: checks ON.
          default = mkPkg {
            buildFeatures = [ "native" ];
            withFrontend = false;
            checksEnabled = true;
          };

          with-frontend = mkPkg {
            buildFeatures = [ "native" "frontend" ];
            withFrontend = true;
            checksEnabled = true;
          };

          # Explicit no-check variants (nice for users).
          no-check = mkPkg {
            buildFeatures = [ "native" ];
            withFrontend = false;
            checksEnabled = false;
          };

          with-frontend-no-check = mkPkg {
            buildFeatures = [ "native" "frontend" ];
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
