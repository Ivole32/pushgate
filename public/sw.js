// Service worker: displays pushed notifications. Payload fields are used only as plain-text
// strings for showNotification(); nothing from the payload is ever treated as markup, URL or
// code. Clicking a notification always opens this app's own start page.

const MAX_TITLE = 200;
const MAX_BODY = 2100;

self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (event) => event.waitUntil(self.clients.claim()));

function text(value, max) {
  return typeof value === 'string' ? value.slice(0, max) : '';
}

// The sender (the server-assigned key name) leads the title: the lock screen always shows the
// title, but only the first lines of the body, so attribution there could be pushed out of
// view or imitated by the sender's own text.
function toNotification(data) {
  const d = data && typeof data === 'object' ? data : {};
  const service = text(d.service, 64);
  const title = text(d.title, MAX_TITLE) || 'Notification';
  const options = {
    body: text(d.body, MAX_BODY),
    icon: '/icons/icon-192.png',
    badge: '/icons/icon-192.png',
    data: { id: text(d.id, 64) },
  };
  if (typeof d.tag === 'string' && /^[A-Za-z0-9_-]{1,32}$/.test(d.tag)) {
    options.tag = d.tag;
    options.renotify = true;
  }
  if (Number.isSafeInteger(d.ts)) options.timestamp = d.ts;
  return { title: service ? `${service}: ${title}` : title, options };
}

self.addEventListener('push', (event) => {
  let data;
  try {
    data = event.data ? event.data.json() : null;
  } catch {
    data = null;
  }
  // iOS revokes push permission if a push does not display a notification, so always show one.
  const { title, options } = toNotification(data);
  event.waitUntil(self.registration.showNotification(title, options));
});

self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  event.waitUntil((async () => {
    const windows = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
    for (const w of windows) {
      if (new URL(w.url).origin === self.location.origin) return w.focus();
    }
    return self.clients.openWindow('/');
  })());
});
