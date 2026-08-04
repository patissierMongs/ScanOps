export function deadlinePatchValue(value) {
  return value ? `${value}T00:00:00` : null;
}
