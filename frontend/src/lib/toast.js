export function toastAnnouncement(type = "") {
  return type === "err"
    ? { role: "alert", live: "assertive" }
    : { role: "status", live: "polite" };
}

export function toastDuration(opts = {}) {
  return opts.timeout ?? (opts.action ? 6000 : 3000);
}
