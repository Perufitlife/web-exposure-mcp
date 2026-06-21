#!/usr/bin/env node
import { runCli } from "./scan.js";
runCli().catch((e) => { console.error(e.message); process.exit(1); });
