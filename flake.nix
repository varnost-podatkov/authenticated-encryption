{
  description = "Authenticated encryption development environment";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { nixpkgs, ... }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
    in
    {
      devShells = forAllSystems (system:
        let pkgs = nixpkgs.legacyPackages.${system}; in
        {
          default = pkgs.mkShell {
            packages = [
              pkgs.python312
              pkgs.git
              pkgs.uv
              pkgs.stdenv.cc.cc.lib
            ];
            shellHook = ''
              # Make libstdc++ visible to wheels like pyzmq (manylinux).
              export LD_LIBRARY_PATH="${pkgs.stdenv.cc.cc.lib}/lib''${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

              export VENV_DIR=.venv
              if [ ! -d "$VENV_DIR" ]; then
                ${pkgs.uv}/bin/uv venv "$VENV_DIR"
              fi
              source "$VENV_DIR/bin/activate"

              if [ -f requirements.txt ]; then
                ${pkgs.uv}/bin/uv pip install -r requirements.txt
              fi
            '';
          };
        });
    };
}
