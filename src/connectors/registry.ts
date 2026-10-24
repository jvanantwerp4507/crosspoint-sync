import { fetch as undiciFetch } from 'undici';
import type { Connector, HttpTransport } from './types.js';
import { assertAllowedUrl, ssrfDispatcher } from '../net/ssrf.js';
import { hardcoverConnector } from './hardcover.js';
import { readwiseConnector } from './readwise.js';
import { readwiseReaderConnector } from './readwise-reader.js';
import { kosyncConnector } from './kosync.js';
import { bookfusionConnector } from './bookfusion.js';
import { audiobookshelfConnector } from './audiobookshelf.js';
import { microblogConnector } from './microblog.js';
import { kindleConnector } from './kindle.js';
import { bookorbitConnector } from './bookorbit.js';
import { spotifyConnector } from './spotify.js';

/** All connectors known to this build. */
const CONNECTORS: Connector[] = [
  kosyncConnector,
  hardcoverConnector,
  readwiseConnector,
  readwiseReaderConnector,
  bookfusionConnector,
  audiobookshelfConnector,
  bookorbitConnector,
  spotifyConnector,
  microblogConnector,
  kindleConnector,
];

const byId = new Map(CONNECTORS.map((c) => [c.id, c]));

/** Connectors shown in the UI/API (excludes hidden ones). */
export function listConnectors(): Connector[] {
  return CONNECTORS.filter((c) => !c.hidden);
}

export function getConnector(id: string): Connector | undefined {
  return byId.get(id);
}

/**
 * Default transport: undici fetch through an SSRF-guarded dispatcher. The URL is
 * validated (http(s) only, no literal private IPs) and every connection - the
 * initial request and any redirect hop - is checked at the socket layer against
 * reserved/private ranges. See src/net/ssrf.ts.
 */
export const fetchTransport: HttpTransport = async (url, init) => {
  assertAllowedUrl(url);
  const res = await undiciFetch(url, { ...init, dispatcher: ssrfDispatcher() });
  return {
    // undici's ReadableStream type differs nominally from the DOM lib's; the
    // runtime stream is the same, so narrow it for the HttpTransport contract.
    body: res.body as ReadableStream<Uint8Array> | null,
    status: res.status,
    text: () => res.text(),
    json: () => res.json(),
  };
};
