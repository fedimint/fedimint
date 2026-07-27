// scripts/bundle.ts
import { bundle } from "https://deno.land/x/emit@0.40.0/mod.ts";

const result = await bundle("scripts/embassy.ts");

await Deno.writeTextFile("scripts/embassy.js", result.code);
