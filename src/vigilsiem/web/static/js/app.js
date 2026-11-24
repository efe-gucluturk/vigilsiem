// Alpine (CSP build) components: no inline expressions, no eval.
document.addEventListener("alpine:init", () => {
  Alpine.data("slideover", () => ({
    open: false,
    show() { this.open = true; },
    close() { this.open = false; },
  }));
});

// Expired/invalid session on any background request -> back to the login page.
document.addEventListener("htmx:responseError", (event) => {
  if (event.detail.xhr && event.detail.xhr.status === 401) {
    window.location.href = "/login";
  }
});
