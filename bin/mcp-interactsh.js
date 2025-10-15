#!/usr/bin/env node
import { main } from '../src/server.js';

// Simple CLI entrypoint to run the MCP server over stdio
main().catch((err) => {
  console.error(err);
  process.exit(1);
});

