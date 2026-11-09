{ lib }:
regexes: src:
let
  basePath = toString src + "/";
in
lib.cleanSourceWith {
  filter =
    path: type:
    let
      relPath = lib.removePrefix basePath (toString path);
      # Prune the directory itself, not just its files: otherwise new skill
      # directories survive as empty directories and change the source hash.
      isSkill = relPath == ".agents/skills" || lib.hasPrefix ".agents/skills/" relPath;
    in
    !isSkill && ((type == "directory") || lib.any (re: builtins.match re relPath != null) regexes);
  inherit src;
}
