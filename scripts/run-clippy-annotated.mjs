import { spawn } from "node:child_process";

const args = [
  "clippy",
  "--manifest-path",
  "src-tauri/Cargo.toml",
  "--workspace",
  "--all-targets",
  "--",
  "-D",
  "warnings",
];
const cargo = process.platform === "win32" ? "cargo.exe" : "cargo";
const child = spawn(cargo, args, {
  env: process.env,
  stdio: ["inherit", "pipe", "pipe"],
});

const MAX_TAIL = 14_000;
let tail = "";
function mirror(stream, destination) {
  stream.on("data", (chunk) => {
    destination.write(chunk);
    tail = `${tail}${chunk.toString("utf8")}`.slice(-MAX_TAIL);
  });
}
mirror(child.stdout, process.stdout);
mirror(child.stderr, process.stderr);

function annotationEscape(value) {
  return value
    .replace(/\u001b\[[0-9;]*m/g, "")
    .replaceAll("%", "%25")
    .replaceAll("\r", "%0D")
    .replaceAll("\n", "%0A");
}

child.once("error", (error) => {
  console.log(
    `::error title=Clippy process failed::${annotationEscape(error.message)}`,
  );
  process.exitCode = 1;
});

child.once("close", (code, signal) => {
  if (code === 0) return;
  const detail = tail || `cargo clippy ended with code=${code} signal=${signal}`;
  console.log(`::error title=Clippy failed::${annotationEscape(detail)}`);
  process.exitCode = code || 1;
});
