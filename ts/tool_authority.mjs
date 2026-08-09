export function dispatch(grants, schemas, role, tool, args) {
  const key = `${role}|${tool}`;
  if (!grants.has(key)) return { status: "REFUSE", reason: "DEFAULT_DENY" };
  const schema = schemas[tool];
  if (!schema) return { status: "REFUSE", reason: "UNKNOWN_TOOL" };
  const missing = schema.required.filter(f => !(f in args));
  if (missing.length) return { status: "REFUSE", reason: "MISSING_ARGS", missing };
  return { status: "ALLOW", reason: null };
}
