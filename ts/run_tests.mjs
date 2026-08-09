import { dispatch } from "./tool_authority.mjs";
import assert from "node:assert/strict";
const grants = new Set(["agent|search"]);
const schemas = { search: { required: ["q"] } };
assert.equal(dispatch(grants, schemas, "agent", "shell", {}).reason, "DEFAULT_DENY");
assert.equal(dispatch(grants, schemas, "agent", "search", {}).reason, "MISSING_ARGS");
assert.equal(dispatch(grants, schemas, "agent", "search", { q: "x" }).status, "ALLOW");
console.log("ok");
