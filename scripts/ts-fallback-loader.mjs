import { promises as fs } from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

export async function resolve(specifier, context, defaultResolve) {
  try {
    return await defaultResolve(specifier, context, defaultResolve);
  } catch (error) {
    if (!isModuleNotFound(error)) {
      throw error;
    }

    if (!context.parentURL || !specifier.endsWith(".js")) {
      throw error;
    }

    if (!isRelativeSpecifier(specifier)) {
      throw error;
    }

    const parentPath = fileURLToPath(context.parentURL);
    const candidatePath = path.resolve(path.dirname(parentPath), specifier.slice(0, -3) + ".ts");

    try {
      await fs.access(candidatePath);
      return {
        url: pathToFileURL(candidatePath).href,
        shortCircuit: true
      };
    } catch {
      throw error;
    }
  }
}

function isModuleNotFound(error) {
  return Boolean(error && typeof error === "object" && error.code === "ERR_MODULE_NOT_FOUND");
}

function isRelativeSpecifier(specifier) {
  return specifier.startsWith("./") || specifier.startsWith("../");
}
