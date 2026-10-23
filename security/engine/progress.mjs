// A successful progress query may describe a failed engine. That is evidence,
// not failure of the query itself; callers need the final engine states.
export function readProgressResponse(value) {
  if (!value || value.ok !== true || value.success === false) throw Error(typeof value?.error === 'string' ? value.error : 'Security progress query failed.');
  return value;
}
