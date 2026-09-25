/**
 * Serving a web-standard handler (`fetch(Request) -> Response`) from `node:http`.
 *
 * The request's signal aborts when the client goes away before the response is written, so a handler that
 * maps a closed HTTP request to cancellation - the auditable MCP HTTP entry does (§6.3) - sees it. The
 * response body is streamed as it is produced, which is what keeps an SSE response live.
 */

import type { IncomingMessage, ServerResponse } from 'node:http';
import { Readable } from 'node:stream';

/** Anything with the web-standard `fetch` face. */
export interface FetchHandler {
  fetch(request: Request): Promise<Response>;
}

const INTERNAL_ERROR_STATUS = 500;
const BODYLESS_METHODS = new Set(['GET', 'HEAD']);

function webRequest(req: IncomingMessage, signal: AbortSignal): Request {
  const url = new URL(req.url ?? '/', `http://${req.headers.host ?? 'localhost'}`);
  const headers = new Headers();
  for (const [name, value] of Object.entries(req.headers)) {
    if (Array.isArray(value)) {
      for (const item of value) {
        headers.append(name, item);
      }
    } else if (value !== undefined) {
      headers.set(name, value);
    }
  }
  const method = req.method ?? 'GET';
  if (BODYLESS_METHODS.has(method.toUpperCase())) {
    return new Request(url, { method, headers, signal });
  }
  return new Request(url, {
    method,
    headers,
    signal,
    body: Readable.toWeb(req),
    duplex: 'half',
  });
}

async function writeResponse(response: Response, res: ServerResponse): Promise<void> {
  res.statusCode = response.status;
  res.statusMessage = response.statusText;
  response.headers.forEach((value, name) => {
    res.setHeader(name, value);
  });
  if (response.body === null) {
    res.end();
    return;
  }
  res.flushHeaders();
  const reader = response.body.getReader();
  res.once('close', () => {
    reader.cancel().catch((error: unknown) => console.debug('auditable-mcp: a response body was not cancelled', error));
  });
  for (;;) {
    const { done, value } = await reader.read();
    if (done) {
      break;
    }
    if (!res.write(value)) {
      await new Promise<void>((resolve) => {
        const done = (): void => {
          res.off('drain', done);
          res.off('close', done);
          resolve();
        };
        res.once('drain', done);
        res.once('close', done);
      });
    }
  }
  res.end();
}

/**
 * A `node:http` request listener that serves `handler`.
 *
 * @param onerror Where a failure to serve a request is reported; it is answered `500` when nothing has been
 *   written yet, and the connection is destroyed otherwise.
 */
export function toNodeListener(
  handler: FetchHandler,
  onerror: (error: unknown) => void = (error) => console.error('auditable-mcp: an HTTP request failed', error),
): (req: IncomingMessage, res: ServerResponse) => void {
  return (req, res) => {
    const controller = new AbortController();
    res.once('close', () => {
      if (!res.writableFinished) {
        controller.abort();
      }
    });
    void (async () => {
      try {
        await writeResponse(await handler.fetch(webRequest(req, controller.signal)), res);
      } catch (error) {
        onerror(error);
        if (res.headersSent) {
          res.destroy();
        } else {
          res.statusCode = INTERNAL_ERROR_STATUS;
          res.end();
        }
      }
    })();
  };
}
