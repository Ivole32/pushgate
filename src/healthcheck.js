// Container health check (the runtime image has no shell or curl).
import http from 'node:http';

const port = Number(process.env.PORT || 8080);
const req = http.get({ host: '127.0.0.1', port, path: '/healthz', timeout: 3000 }, (res) => {
  res.resume();
  process.exit(res.statusCode === 200 ? 0 : 1);
});
req.on('timeout', () => req.destroy());
req.on('error', () => process.exit(1));
