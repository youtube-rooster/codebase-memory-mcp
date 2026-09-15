/*
 * test_io_topology.c — the I/O map a multi-repo workspace needs from the graph.
 *
 * These are behaviour tests, not probes: each one names an observable defect
 * measured against a real workspace (Rooster Control Room) where the graph
 * answered "no I/O" for a service that has plenty.  They run the full pipeline
 * and assert on the resulting graph through `query_graph`, because the defects
 * are in edge PROPERTIES and node IDENTITY, which an edge count cannot see.
 */
#include "../src/foundation/compat.h"
#include "test_framework.h"
#include "test_helpers.h"
#include "cbm.h"
#include <mcp/mcp.h>
#include <store/store.h>
#include <pipeline/pipeline.h>
#include <foundation/log.h>

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>

typedef struct {
    char tmpdir[512];
    char dbpath[600];
    char *project;
    cbm_mcp_server_t *srv;
} IoProj;

typedef struct {
    const char *name;
    const char *content;
} IoFile;

/* Index `files` into a fresh project and leave the MCP server open so the
 * caller can query the graph it produced. */
static int io_index(IoProj *p, const IoFile *files, int nfiles) {
    memset(p, 0, sizeof(*p));
    snprintf(p->tmpdir, sizeof(p->tmpdir), "/tmp/cbm_io_XXXXXX");
    if (!cbm_mkdtemp(p->tmpdir)) {
        return 0;
    }
    for (char *c = p->tmpdir; *c; c++) {
        if (*c == '\\') {
            *c = '/';
        }
    }
    for (int i = 0; i < nfiles; i++) {
        char path[700];
        snprintf(path, sizeof(path), "%s/%s", p->tmpdir, files[i].name);
        char *slash = strrchr(path, '/');
        if (slash && slash > path + strlen(p->tmpdir)) {
            *slash = '\0';
            cbm_mkdir_p(path, 0755);
            *slash = '/';
        }
        FILE *f = fopen(path, "wb");
        if (!f) {
            return 0;
        }
        fputs(files[i].content, f);
        fclose(f);
    }
    p->project = cbm_project_name_from_path(p->tmpdir);
    if (!p->project) {
        return 0;
    }
    const char *home = getenv("HOME");
    if (!home) {
        home = "/tmp";
    }
    char cache_dir[512];
    snprintf(cache_dir, sizeof(cache_dir), "%s/.cache/codebase-memory-mcp", home);
    cbm_mkdir(cache_dir);
    snprintf(p->dbpath, sizeof(p->dbpath), "%s/%s.db", cache_dir, p->project);
    unlink(p->dbpath);
    p->srv = cbm_mcp_server_new(NULL);
    if (!p->srv) {
        return 0;
    }
    char args[700];
    snprintf(args, sizeof(args), "{\"repo_path\":\"%s\"}", p->tmpdir);
    char *resp = cbm_mcp_handle_tool(p->srv, "index_repository", args);
    if (resp) {
        free(resp);
    }
    return 1;
}

/* Run a Cypher query and return the raw tool response (caller frees). */
static char *io_query(IoProj *p, const char *cypher) {
    char args[1400];
    snprintf(args, sizeof(args), "{\"project\":\"%s\",\"query\":\"%s\"}", p->project, cypher);
    return cbm_mcp_handle_tool(p->srv, "query_graph", args);
}

/* True when the query result mentions `needle`. */
static int io_query_has(IoProj *p, const char *cypher, const char *needle) {
    char *resp = io_query(p, cypher);
    int found = resp && strstr(resp, needle) != NULL;
    if (!found && resp) {
        fprintf(stderr, "      └─ query [%s] missing [%s]\n", cypher, needle);
    }
    if (resp) {
        free(resp);
    }
    return found;
}

static void io_cleanup(IoProj *p) {
    if (p->srv) {
        cbm_mcp_server_free(p->srv);
        p->srv = NULL;
    }
    free(p->project);
    p->project = NULL;
    th_rmtree(p->tmpdir);
    unlink(p->dbpath);
    char side[700];
    snprintf(side, sizeof(side), "%s-wal", p->dbpath);
    unlink(side);
    snprintf(side, sizeof(side), "%s-shm", p->dbpath);
    unlink(side);
}

/* ══════════════════════════════════════════════════════════════════
 * 1. Python route attribution — the HANDLES edge must name the file
 *    that declared the route, as the JS registration path already does.
 *    Without it every route in a Python service is attributed to the
 *    repo instead of the module, which is how seven modules of one repo
 *    ended up publishing the same 331 routes.
 * ══════════════════════════════════════════════════════════════════ */
TEST(py_decorator_route_handles_carries_decl_file) {
    const IoFile f[] = {
        {"app/routes.py", "from fastapi import FastAPI\n"
                          "app = FastAPI()\n\n"
                          "@app.get('/reports/{id}')\n"
                          "def get_report(id: str):\n"
                          "    return {'id': id}\n"},
    };
    IoProj p;
    ASSERT_TRUE(io_index(&p, f, 1));
    int ok = io_query_has(&p, "MATCH (a)-[h:HANDLES]->(b) RETURN h.decl_file", "app/routes.py");
    io_cleanup(&p);
    ASSERT_TRUE(ok);
    PASS();
}

/* A route declared inside a test file is a fixture, not a service surface.
 * Counting it makes the biggest route declarer of a repo a test module. */
TEST(py_route_declared_in_a_test_file_is_not_a_route) {
    const IoFile f[] = {
        {"app/routes.py", "from fastapi import FastAPI\n"
                          "app = FastAPI()\n\n"
                          "@app.get('/real')\n"
                          "def real():\n"
                          "    return 1\n"},
        {"tests/test_routes.py", "from fastapi import FastAPI\n"
                                 "app = FastAPI()\n\n"
                                 "@app.get('/fixture-only')\n"
                                 "def fixture_only():\n"
                                 "    return 1\n"},
    };
    IoProj p;
    ASSERT_TRUE(io_index(&p, f, 2));
    int has_real = io_query_has(&p, "MATCH (r:Route) RETURN r.name", "/real");
    char *resp = io_query(&p, "MATCH (r:Route) RETURN r.name");
    int has_fixture = resp && strstr(resp, "/fixture-only") != NULL;
    if (resp) {
        free(resp);
    }
    io_cleanup(&p);
    ASSERT_TRUE(has_real);
    ASSERT_TRUE(!has_fixture);
    PASS();
}

/* ══════════════════════════════════════════════════════════════════
 * 2. Python class constants — `Queues.ALL_PROCESSED` is a name only the
 *    defining file can resolve, and the defining file is never the one
 *    that publishes.  Left unresolved, a Python producer can never match
 *    the JS consumer that names the same queue as a literal.
 * ══════════════════════════════════════════════════════════════════ */
TEST(py_class_constant_channel_resolves_to_its_literal) {
    const IoFile f[] = {
        {"shared/config.py", "class Queues:\n"
                             "    ALL_PROCESSED = \"all-processed.queue\"\n"
                             "    MODERATION = \"comments.moderation.queue\"\n"},
        {"worker/publisher.py", "import pika\n"
                                "from shared.config import Queues\n\n"
                                "def publish(channel, body):\n"
                                "    channel.basic_publish(exchange='', "
                                "routing_key=Queues.ALL_PROCESSED, body=body)\n"},
    };
    IoProj p;
    ASSERT_TRUE(io_index(&p, f, 2));
    int resolved = io_query_has(&p, "MATCH (c:Channel) RETURN c.name", "all-processed.queue");
    char *resp = io_query(&p, "MATCH (c:Channel) RETURN c.name");
    int still_symbolic = resp && strstr(resp, "Queues.ALL_PROCESSED") != NULL;
    if (resp) {
        free(resp);
    }
    io_cleanup(&p);
    ASSERT_TRUE(resolved);
    ASSERT_TRUE(!still_symbolic);
    PASS();
}

/* ══════════════════════════════════════════════════════════════════
 * 3. Consumption declared by inheritance — a worker framework puts the
 *    consume loop in the base class and the queue in a subclass field.
 *    Read literally, every worker in such a codebase is a producer with
 *    no consumer anywhere, which reads as a broken pipeline.
 * ══════════════════════════════════════════════════════════════════ */
TEST(py_worker_subclass_queue_field_is_a_listen) {
    const IoFile f[] = {
        {"shared/config.py", "class Queues:\n"
                             "    MODERATION = \"comments.moderation.queue\"\n"},
        /* The shape a worker framework actually has: the queue is set on the
         * instance in __init__ and handed to consume positionally. */
        {"shared/worker.py", "class AbstractWorker:\n"
                             "    def __init__(self):\n"
                             "        self.queue_name = None\n\n"
                             "    async def register(self):\n"
                             "        await self.state.rabbitmq_client.consume(self.queue_name, "
                             "self.handler)\n"},
        {"worker/moderation.py", "from shared.worker import AbstractWorker\n"
                                 "from shared.config import Queues\n\n"
                                 "class ModerationWorker(AbstractWorker):\n"
                                 "    def __init__(self):\n"
                                 "        super().__init__()\n"
                                 "        self.queue_name = Queues.MODERATION\n\n"
                                 "    def handler(self, msg):\n"
                                 "        return msg\n"},
    };
    IoProj p;
    ASSERT_TRUE(io_index(&p, f, 3));
    int ok = io_query_has(&p, "MATCH ()-[:LISTENS_ON]->(c:Channel) RETURN c.name",
                          "comments.moderation.queue");
    io_cleanup(&p);
    ASSERT_TRUE(ok);
    PASS();
}

/* ══════════════════════════════════════════════════════════════════
 * 3b. The callback handed to `consume` is not a queue.  aio-pika style
 *     clients bind the queue on the receiver (`queue.consume(handler)`),
 *     so the positional fallback that catches `consume(self.queue_name, …)`
 *     read the bound method as a channel and reported a worker listening
 *     on a queue named `self._handle_message`.
 * ══════════════════════════════════════════════════════════════════ */
TEST(py_consume_callback_bound_method_is_not_a_channel) {
    const IoFile f[] = {
        {"polling_service.py", "class PollingService:\n"
                               "    def __init__(self, queue_client):\n"
                               "        self.queue_client = queue_client\n\n"
                               "    async def start(self):\n"
                               "        await self.queue_client.consume(self._handle_message)\n\n"
                               "    async def _handle_message(self, msg):\n"
                               "        return msg\n"},
    };
    IoProj p;
    ASSERT_TRUE(io_index(&p, f, 1));
    int phantom = io_query_has(&p, "MATCH (c:Channel) RETURN c.name", "self._handle_message");
    io_cleanup(&p);
    ASSERT_TRUE(!phantom);
    PASS();
}

/* ══════════════════════════════════════════════════════════════════
 * 4. A browser calling an API does not serve one.  A frontend whose
 *    client calls are read as route registrations reports a route
 *    surface it does not have, and the call never reaches the service
 *    that does serve it.
 * ══════════════════════════════════════════════════════════════════ */
TEST(js_client_call_in_a_frontend_is_not_a_route) {
    const IoFile f[] = {
        {"package.json", "{\"name\":\"front\",\"dependencies\":{\"axios\":\"^1.0.0\"}}\n"},
        {"src/api/client.ts", "import axios from 'axios'\n"
                              "const api = axios.create({ baseURL: '/api' })\n"
                              "export async function loadProviders() {\n"
                              "  const res = await api.get('/oauth2/providers')\n"
                              "  return res.data\n"
                              "}\n"},
    };
    IoProj p;
    ASSERT_TRUE(io_index(&p, f, 2));
    /* The Route node exists — it is what the call points AT, and cross-repo
     * matching needs it.  What must not exist is a HANDLES edge into it: that
     * is the only thing separating a path this repo serves from a path it
     * merely asks for, and reading Route nodes as the served surface is how a
     * frontend reports a route inventory it does not have. */
    int calls_out =
        io_query_has(&p, "MATCH ()-[:HTTP_CALLS]->(b) RETURN b.name", "/oauth2/providers");
    char *resp = io_query(&p, "MATCH (a)-[:HANDLES]->(b) RETURN b.name");
    int claims_to_serve = resp && strstr(resp, "/oauth2/providers") != NULL;
    if (resp) {
        free(resp);
    }
    io_cleanup(&p);
    ASSERT_TRUE(calls_out);
    ASSERT_TRUE(!claims_to_serve);
    PASS();
}

/* ══════════════════════════════════════════════════════════════════
 * 5. A gateway broadcasts ONE socket event carrying a typed envelope,
 *    so the event name says only "this is a message".  The type inside
 *    is the wire name the client listens for; unrecorded, the gateway
 *    publishes nothing a consumer could ever be matched against.
 * ══════════════════════════════════════════════════════════════════ */
TEST(socketio_envelope_emit_records_the_message_type) {
    const IoFile f[] = {
        {"package.json", "{\"name\":\"gw\",\"dependencies\":{\"socket.io\":\"^4.0.0\"}}\n"},
        {"src/gateway.ts", "import { Server } from 'socket.io'\n"
                           "const io = new Server()\n"
                           "export function push(room: string, payload: unknown) {\n"
                           "  io.to(room).emit('message', { type: 'content_engine', payload })\n"
                           "}\n"},
    };
    IoProj p;
    ASSERT_TRUE(io_index(&p, f, 2));
    int ok = io_query_has(&p,
                          "MATCH ()-[:EMITS]->(c:Channel) WHERE c.transport = 'message_type' "
                          "RETURN c.name",
                          "content_engine");
    io_cleanup(&p);
    ASSERT_TRUE(ok);
    PASS();
}

/* ══════════════════════════════════════════════════════════════════
 * 6. `io.to(room).emit(...)` is the socket.io broadcast idiom.  Read on
 *    the text of the receiver it looks like a call to `to`, so every
 *    room-scoped broadcast a gateway makes went unrecorded while the
 *    direct `socket.emit` on the line above it resolved.
 * ══════════════════════════════════════════════════════════════════ */
TEST(js_room_scoped_socketio_broadcast_is_an_emit) {
    const IoFile f[] = {
        {"package.json", "{\"name\":\"gw\",\"dependencies\":{\"socket.io\":\"^4.0.0\"}}\n"},
        {"src/gateway.ts", "import { Server } from 'socket.io'\n"
                           "const io = new Server()\n"
                           "export function push(liveId: string, payload: unknown) {\n"
                           "  io.to(`members:${liveId}`).emit('member_comments', payload)\n"
                           "}\n"},
    };
    IoProj p;
    ASSERT_TRUE(io_index(&p, f, 2));
    int ok = io_query_has(&p,
                          "MATCH ()-[:EMITS]->(c:Channel) WHERE c.transport = 'socketio' "
                          "RETURN c.name",
                          "member_comments");
    io_cleanup(&p);
    ASSERT_TRUE(ok);
    PASS();
}

/* ══════════════════════════════════════════════════════════════════
 * 7. Cross-repo: a gateway that emits a typed envelope and a client
 *    that listens for that type are the two ends of one socket.  Held
 *    to exact transport equality, the emit is filed as a message type
 *    and the listen as a socket event, and the edge is never drawn —
 *    which reads as two services that do not talk.
 * ══════════════════════════════════════════════════════════════════ */
TEST(cross_repo_socketio_listen_matches_message_type_emit) {
    const IoFile gw[] = {
        {"package.json", "{\"name\":\"gw\",\"dependencies\":{\"socket.io\":\"^4.0.0\"}}\n"},
        {"src/gateway.ts", "import { Server } from 'socket.io'\n"
                           "const io = new Server()\n"
                           "export function push(room: string, event: string, p: unknown) {\n"
                           "  io.to(room).emit('message', { type: 'content_engine', payload: p })\n"
                           "}\n"},
    };
    const IoFile front[] = {
        {"package.json",
         "{\"name\":\"front\",\"dependencies\":{\"socket.io-client\":\"^4.0.0\"}}\n"},
        {"src/live.ts", "import { io } from 'socket.io-client'\n"
                        "const socket = io()\n"
                        "socket.on('content_engine', (p) => console.log(p))\n"},
    };
    IoProj g;
    IoProj f;
    ASSERT_TRUE(io_index(&g, gw, 2));
    ASSERT_TRUE(io_index(&f, front, 2));

    char args[1400];
    snprintf(args, sizeof(args),
             "{\"repo_path\":\"%s\",\"mode\":\"cross-repo-intelligence\","
             "\"target_projects\":[\"%s\"]}",
             g.tmpdir, f.project);
    char *resp = cbm_mcp_handle_tool(g.srv, "index_repository", args);
    int linked = resp && strstr(resp, "\"cross_channel\":0") == NULL &&
                 strstr(resp, "cross_channel") != NULL;
    if (!linked && resp) {
        fprintf(stderr, "      └─ cross-repo: %s\n", resp);
    }
    if (resp) {
        free(resp);
    }
    io_cleanup(&f);
    io_cleanup(&g);
    ASSERT_TRUE(linked);
    PASS();
}

/* ══════════════════════════════════════════════════════════════════
 * 9. An AMQP publish names an exchange AND a routing key.  Recorded as two
 *    channels, the exchange has no key and the key has no exchange, and
 *    the broker's bindings — which route (exchange, key) → queue — can
 *    never be applied.  The key belongs on the EMITS edge.
 * ══════════════════════════════════════════════════════════════════ */
TEST(py_publish_carries_routing_key_on_the_emits_edge) {
    const IoFile f[] = {
        {"shared/config.py", "class Exchanges:\n"
                             "    PROCESSED = \"comments.processed.exchange\"\n\n"
                             "class RoutingKeys:\n"
                             "    BATCH = \"comments.batch.processed\"\n"},
        {"worker/publisher.py",
         "from shared.config import Exchanges, RoutingKeys\n\n"
         "async def publish_batch(client, body):\n"
         "    await client.rabbitmq_client.publish(exchange=Exchanges.PROCESSED, message=body, "
         "routing_key=RoutingKeys.BATCH)\n\n"
         "def publish_pika(channel, body):\n"
         "    channel.basic_publish(exchange=\"comments.processed.exchange\", "
         "routing_key=\"comments.processed\", body=body)\n\n"
         "async def publish_aio(exchange, body):\n"
         "    await exchange.publish(body, routing_key=\"notifications.questions\")\n\n"
         "async def publish_plain(client, body):\n"
         "    await client.rabbitmq_client.publish(queue_name=\"all-processed.queue\", "
         "message=body)\n"},
    };
    IoProj p;
    ASSERT_TRUE(io_index(&p, f, 2));
    char *names = io_query(&p, "MATCH ()-[:EMITS]->(c:Channel) RETURN c.name");
    int exchange_is_channel = names && strstr(names, "comments.processed.exchange") != NULL;
    int key_is_not_a_channel = names && strstr(names, "comments.batch.processed") == NULL &&
                               strstr(names, "comments.processed\"") == NULL;
    int aio_key_is_the_channel = names && strstr(names, "notifications.questions") != NULL;
    int plain_queue_kept = names && strstr(names, "all-processed.queue") != NULL;
    if (names) {
        free(names);
    }
    char *keys = io_query(&p, "MATCH ()-[e:EMITS]->(c:Channel) RETURN c.name, e.routing_keys");
    int symbolic_key_resolved = keys && strstr(keys, "comments.batch.processed") != NULL &&
                                strstr(keys, "RoutingKeys.BATCH") == NULL;
    /* The array is JSON inside the tool's JSON, so the closing quote of the
     * key arrives escaped — and it is that backslash which tells the bare key
     * apart from the `comments.processed.exchange` prefix. */
    int literal_key_kept = keys && strstr(keys, "comments.processed\\") != NULL;
    if (keys) {
        free(keys);
    }
    io_cleanup(&p);
    ASSERT_TRUE(exchange_is_channel);
    ASSERT_TRUE(key_is_not_a_channel);
    ASSERT_TRUE(aio_key_is_the_channel);
    ASSERT_TRUE(plain_queue_kept);
    ASSERT_TRUE(symbolic_key_resolved);
    ASSERT_TRUE(literal_key_kept);
    PASS();
}

TEST(py_two_keys_on_one_exchange_from_one_function_are_both_kept) {
    const IoFile f[] = {
        {"worker/publisher.py", "def publish_both(channel, body):\n"
                                "    channel.basic_publish(exchange=\"live.control.exchange\", "
                                "routing_key=\"live.control.start\", body=body)\n"
                                "    channel.basic_publish(exchange=\"live.control.exchange\", "
                                "routing_key=\"live.control.stop\", body=body)\n"},
    };
    IoProj p;
    ASSERT_TRUE(io_index(&p, f, 1));
    char *keys = io_query(&p, "MATCH ()-[e:EMITS]->(c:Channel) RETURN e.routing_keys");
    int both = keys && strstr(keys, "live.control.start") != NULL &&
               strstr(keys, "live.control.stop") != NULL;
    if (keys) {
        free(keys);
    }
    io_cleanup(&p);
    ASSERT_TRUE(both);
    PASS();
}

TEST(js_amqplib_publish_carries_routing_key_on_the_emits_edge) {
    const IoFile f[] = {
        {"src/services/rabbitmq.js",
         "export async function sendNotificationMessage(channel, message) {\n"
         "  await channel.publish(\"notifications.insights.exchange\", "
         "\"notifications.highlight_comments\", Buffer.from(JSON.stringify(message)));\n"
         "}\n\n"
         "export async function sendDirect(channel, message) {\n"
         "  await channel.sendToQueue(\"all-processed.queue\", Buffer.from(message));\n"
         "}\n"},
    };
    IoProj p;
    ASSERT_TRUE(io_index(&p, f, 1));
    char *rows = io_query(&p, "MATCH ()-[e:EMITS]->(c:Channel) RETURN c.name, e.routing_keys");
    int exchange_keyed = rows && strstr(rows, "notifications.insights.exchange") != NULL &&
                         strstr(rows, "notifications.highlight_comments") != NULL;
    int queue_unkeyed = rows && strstr(rows, "all-processed.queue") != NULL;
    if (rows) {
        free(rows);
    }
    int key_is_not_a_channel =
        !io_query_has(&p, "MATCH (c:Channel) RETURN c.name", "notifications.highlight_comments");
    io_cleanup(&p);
    ASSERT_TRUE(exchange_keyed);
    ASSERT_TRUE(queue_unkeyed);
    ASSERT_TRUE(key_is_not_a_channel);
    PASS();
}

/* ══════════════════════════════════════════════════════════════════
 * 10. The broker definitions file is part of the graph: exchanges and
 *     queues become Channel nodes and every binding a BINDS edge whose
 *     routing keys accumulate — ten `notifications.*` keys join one
 *     exchange to one queue, and the store holds one edge per pair.
 * ══════════════════════════════════════════════════════════════════ */
TEST(rabbitmq_definitions_file_becomes_binds_edges) {
    const IoFile f[] = {
        {"rabbitmq/definitions.json",
         "{\"exchanges\": [{\"name\": \"notifications.insights.exchange\"}],\n"
         " \"queues\": [{\"name\": \"notifications.insights.queue\"}],\n"
         " \"bindings\": [\n"
         "  {\"source\": \"notifications.insights.exchange\", \"destination\": "
         "\"notifications.insights.queue\", \"destination_type\": \"queue\", "
         "\"routing_key\": \"notifications.questions\"},\n"
         "  {\"source\": \"notifications.insights.exchange\", \"destination\": "
         "\"notifications.insights.queue\", \"destination_type\": \"queue\", "
         "\"routing_key\": \"notifications.hashtags\"}\n"
         " ]}\n"},
    };
    IoProj p;
    ASSERT_TRUE(io_index(&p, f, 1));
    char *rows = io_query(
        &p, "MATCH (e:Channel)-[b:BINDS]->(q:Channel) RETURN e.name, q.name, b.routing_keys");
    int bound = rows && strstr(rows, "notifications.insights.exchange") != NULL &&
                strstr(rows, "notifications.insights.queue") != NULL &&
                strstr(rows, "notifications.questions") != NULL &&
                strstr(rows, "notifications.hashtags") != NULL;
    int rows_seen = 0;
    for (const char *at = rows; at && (at = strstr(at, "notifications.insights.queue")) != NULL;
         at++) {
        rows_seen++;
    }
    int one_edge = rows_seen == 1;
    if (rows) {
        free(rows);
    }
    io_cleanup(&p);
    ASSERT_TRUE(bound);
    ASSERT_TRUE(one_edge);
    PASS();
}

SUITE(io_topology) {
    RUN_TEST(py_publish_carries_routing_key_on_the_emits_edge);
    RUN_TEST(py_two_keys_on_one_exchange_from_one_function_are_both_kept);
    RUN_TEST(js_amqplib_publish_carries_routing_key_on_the_emits_edge);
    RUN_TEST(rabbitmq_definitions_file_becomes_binds_edges);
    RUN_TEST(py_decorator_route_handles_carries_decl_file);
    RUN_TEST(py_route_declared_in_a_test_file_is_not_a_route);
    RUN_TEST(py_class_constant_channel_resolves_to_its_literal);
    RUN_TEST(py_worker_subclass_queue_field_is_a_listen);
    RUN_TEST(py_consume_callback_bound_method_is_not_a_channel);
    RUN_TEST(js_client_call_in_a_frontend_is_not_a_route);
    RUN_TEST(socketio_envelope_emit_records_the_message_type);
    RUN_TEST(js_room_scoped_socketio_broadcast_is_an_emit);
    RUN_TEST(cross_repo_socketio_listen_matches_message_type_emit);
}
