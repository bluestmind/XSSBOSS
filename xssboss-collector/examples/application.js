import DOMPurify from "dompurify";

export function renderGreeting(element) {
  const name = new URLSearchParams(location.search).get("name");
  const safeName = DOMPurify.sanitize(name);
  element.innerHTML = safeName;
  return safeName;
}

export async function recordNavigation(url) {
  await fetch("/api/navigation", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({url})
  });
  return url;
}

window.addEventListener("message", (event) => {
  const destination = event.data.url;
  window.location.href = destination;
});
