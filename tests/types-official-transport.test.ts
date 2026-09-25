/**
 * The seams interoperate with the official MCP SDK's transports without casts.
 *
 * This file is type-checked by `tsc --noEmit` under the repository's tsconfig
 * (`exactOptionalPropertyTypes` on); every construction below fails the build if a seam and an official
 * `Transport` stop being assignable to each other in either direction.
 */

import {
  type Client,
  type Transport as ClientTransport,
  InMemoryTransport,
  StreamableHTTPClientTransport,
} from '@modelcontextprotocol/client';
import { StdioClientTransport } from '@modelcontextprotocol/client/stdio';
import {
  McpServer,
  type Transport as ServerTransport,
  WebStandardStreamableHTTPServerTransport,
} from '@modelcontextprotocol/server';
import { StdioServerTransport, serveStdio } from '@modelcontextprotocol/server/stdio';
import { describe, expect, it } from 'vitest';
import { AuditHost } from '../src/host';
import { McpAuditReceiver, McpAuditTransport } from '../src/mcp';
import { createAuditableMcpHandler } from '../src/mcp/http';
import { type AuditCapability, Countersign, Level, SPEC_VERSION } from '../src/models';
import { type FetchHandler, toNodeListener } from '../src/node';

const CAP: AuditCapability = {
  spec_version: SPEC_VERSION,
  level: Level.L1,
  attempt: 'request',
  countersign: Countersign.NONE,
};

describe('the seams and the official MCP transports', () => {
  it('wrap an official transport and are accepted by the official API without a cast', () => {
    const toolSide = new McpAuditTransport(new StdioServerTransport(), CAP);
    const asServerTransport: ServerTransport = toolSide;
    const serve = (): ReturnType<typeof serveStdio> =>
      serveStdio(() => new McpServer({ name: 't', version: '0' }), { transport: toolSide });

    const host = new AuditHost('tenant-a', CAP);
    const hostSide = new McpAuditReceiver(
      new StdioClientTransport({ command: process.execPath, args: ['--version'] }),
      host,
    );
    const asClientTransport: ClientTransport = hostSide;
    const connect = (client: Client): Promise<void> => client.connect(hostSide);

    const [clientWire, serverWire] = InMemoryTransport.createLinkedPair();
    const inMemory = [new McpAuditTransport(serverWire, CAP), new McpAuditReceiver(clientWire, host)];

    expect([asServerTransport, asClientTransport, serve, connect, ...inMemory]).toHaveLength(6);
  });

  it('wrap the official Streamable HTTP transports, and the HTTP entry serves from node:http, without a cast', async () => {
    const host = new AuditHost('tenant-a', CAP);
    const hostSide: ClientTransport = new McpAuditReceiver(
      new StreamableHTTPClientTransport(new URL('http://127.0.0.1:1/mcp')),
      host,
    );
    const toolSide: ServerTransport = new McpAuditTransport(new WebStandardStreamableHTTPServerTransport(), CAP);
    const handler = createAuditableMcpHandler(
      (audit) => {
        const server = new McpServer({ name: 't', version: '0' });
        server.registerTool('t', { description: 't' }, (ctx) => {
          audit.call(ctx.mcpReq.id);
          return { content: [] };
        });
        return server;
      },
      { declares: CAP },
    );
    const asFetchHandler: FetchHandler = handler;
    expect([hostSide, toolSide, toNodeListener(asFetchHandler)]).toHaveLength(3);
    await handler.close();
  });
});
