// Narrows ajv errors to the ones that explain a failure, and formats them
// with stable `schema/<keyword>` reason codes. Shared by the vector and
// Shared Objects validators.

// Keeps the errors that explain a failure: drops combinator summaries and
// any error whose location is an ancestor of a more specific error.
export function relevant(errors) {
  const kept = errors.filter((e) => !["anyOf", "oneOf", "if"].includes(e.keyword));
  const paths = kept.map((e) => e.instancePath);
  const leafy = kept.filter((e) => !paths.some((p) => p !== e.instancePath && p.startsWith(`${e.instancePath}/`)));
  const seen = new Set();
  return leafy.filter((e) => {
    const key = `${e.instancePath} ${e.keyword} ${e.message}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

export function schemaReason(e) {
  const extra = e.params?.unevaluatedProperty ?? e.params?.additionalProperty ?? e.params?.propertyName;
  return `schema/${e.keyword}: ${e.message}${extra ? ` (${extra})` : ""}`;
}
