const esbuild = require("esbuild");
const path = require("path");
const fs = require("fs");

const isProduction = process.argv.includes("--production");
const isWatch = process.argv.includes("--watch");

const projectRoot = __dirname;
const srcDir = path.join(projectRoot, "src");
const distDir = path.join(projectRoot, "dist");

/**
 * Copy a directory recursively.
 */
function copyDirSync(source, destination) {
  if (!fs.existsSync(source)) {
    return;
  }

  fs.mkdirSync(destination, { recursive: true });

  for (const entry of fs.readdirSync(source, { withFileTypes: true })) {
    const sourcePath = path.join(source, entry.name);
    const destinationPath = path.join(destination, entry.name);

    if (entry.isDirectory()) {
      copyDirSync(sourcePath, destinationPath);
    } else {
      fs.copyFileSync(sourcePath, destinationPath);
    }
  }
}

/**
 * Copy runtime assets that are referenced by the bundled extension.
 *
 * Note:
 * The regex/ and stringgroup/ databases are NOT copied here.
 * They remain at the extension root so the database layer can load them
 * through ExtensionContext.extensionPath.
 */
const copyRuntimeAssetsPlugin = {
  name: "copy-runtime-assets",

  setup(build) {
    build.onEnd((result) => {
      if (result.errors.length > 0) {
        return;
      }

      fs.mkdirSync(distDir, { recursive: true });

      // Dashboard web assets
      const dashboardSource = path.join(
        srcDir,
        "vscode",
        "views",
        "dashboard"
      );

      const dashboardDestination = path.join(
        distDir,
        "dashboard"
      );

      if (fs.existsSync(dashboardSource)) {
        copyDirSync(dashboardSource, dashboardDestination);
      }

      // Notification / alert sounds
      const soundsSource = path.join(
        projectRoot,
        "media",
        "sounds"
      );

      const soundsDestination = path.join(
        distDir,
        "sounds"
      );

      if (fs.existsSync(soundsSource)) {
        copyDirSync(soundsSource, soundsDestination);
      }

      console.log(
        `[Keymontr] Build complete: ${isProduction ? "production" : "development"}`
      );
    });
  },
};

/**
 * esbuild aliases.
 *
 * These must match the aliases defined in tsconfig.json.
 */
const aliasPlugin = {
  name: "keymontr-aliases",

  setup(build) {
    const aliases = {
      "@core": path.join(srcDir, "core"),
      "@database": path.join(srcDir, "database"),
      "@vscode": path.join(srcDir, "vscode"),
      "@git": path.join(srcDir, "git"),
      "@remediation": path.join(srcDir, "remediation"),
      "@storage": path.join(srcDir, "storage"),
      "@config": path.join(srcDir, "config"),
      "@ai": path.join(srcDir, "ai"),
    };

    for (const [alias, directory] of Object.entries(aliases)) {
      build.onResolve(
        { filter: new RegExp(`^${alias.replace("@", "\\@")}(\\/.*)?$`) },
        (args) => {
          const relativePath = args.path.slice(alias.length);

          return {
            path: path.join(directory, relativePath),
          };
        }
      );
    }
  },
};

/**
 * Report useful esbuild errors in the terminal.
 */
const problemMatcherPlugin = {
  name: "keymontr-problem-matcher",

  setup(build) {
    build.onStart(() => {
      if (isWatch) {
        console.log("[Keymontr] Build started...");
      }
    });

    build.onEnd((result) => {
      for (const error of result.errors) {
        console.error(`[Keymontr] ERROR: ${error.text}`);

        if (error.location) {
          console.error(
            `  ${error.location.file}:${error.location.line}:${error.location.column}`
          );
        }
      }

      if (isWatch && result.errors.length === 0) {
        console.log("[Keymontr] Build finished.");
      }
    });
  },
};

const buildOptions = {
  entryPoints: [
    path.join(srcDir, "extension.ts")
  ],

  bundle: true,

  outfile: path.join(
    distDir,
    "extension.js"
  ),

  format: "cjs",

  platform: "node",

  // VS Code's current desktop/remote extension host uses Node 22.
  target: "node22",

  external: [
    "vscode"
  ],

  sourcemap: isProduction ? false : true,

  sourcesContent: !isProduction,

  minify: isProduction,

  treeShaking: true,

  legalComments: "none",

  charset: "utf8",

  logLevel: "warning",

  define: {
    "process.env.NODE_ENV": JSON.stringify(
      isProduction ? "production" : "development"
    )
  },

  plugins: [
    aliasPlugin,
    copyRuntimeAssetsPlugin,
    problemMatcherPlugin
  ]
};

async function main() {
  try {
    const context = await esbuild.context(buildOptions);

    if (isWatch) {
      await context.watch();

      console.log("[Keymontr] Watching for changes...");

      return;
    }

    await context.rebuild();
    await context.dispose();
  } catch (error) {
    console.error("[Keymontr] Build failed.");

    if (error instanceof Error) {
      console.error(error.message);
    } else {
      console.error(error);
    }

    process.exitCode = 1;
  }
}

main();