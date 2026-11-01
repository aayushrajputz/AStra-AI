#!/usr/bin/env node
"use strict";

const { run } = require("../lib/launcher.js");

run(process.argv.slice(2)).catch(error => {
  console.error(`astra-ai: ${error.message}`);
  process.exitCode = 1;
});
