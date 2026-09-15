/*
 * extract_channels.c — Pub/sub channel participation extractor.
 *
 * Detects event-driven communication patterns across multiple languages:
 *   JS/TS/TSX: Socket.IO, EventEmitter, raw WebSocket, Kafka, RabbitMQ
 *   Python:    python-socketio, Django Channels, FastAPI WebSocket, kafka-python
 *   Go:        gorilla/nhooyr websocket (WriteMessage/ReadMessage)
 *   Java:      JSR 356 WebSocket, Spring STOMP/WebSocket
 *   C#:        SignalR (Hub.SendAsync / Hub.On)
 *   Ruby:      ActionCable (broadcast / stream_from)
 *   Elixir:    Phoenix.PubSub, Phoenix.Channel
 *   Rust:      tokio-tungstenite (sink.send / stream.next)
 *
 * Transport is stored on the record ("socketio", "websocket", "kafka", etc.)
 * so later detectors can share the same schema without changing edge types.
 *
 * String-constant resolution: when the channel name argument is a plain
 * identifier, we perform a single-pass local scan of the module body to
 * resolve `const EVENT = "foo"` style bindings.  Template literals and
 * config-driven names stay unresolved (acceptable — those require real
 * data-flow analysis).
 */
#include "cbm.h"
#include "arena.h"
#include "helpers.h"
#include "foundation/constants.h"
#include "extract_node_stack.h"
#include "tree_sitter/api.h"
#include <stdint.h>
#include <string.h>

enum {
    CHAN_CONST_CAP = 256,  /* max tracked identifiers per file */
    CHAN_IDENT_MAX = 128,  /* max identifier length tracked */
    CHAN_STACK_CAP = 4096, /* traversal stack depth per walk    */
    CHAN_DIR_UNKNOWN = -1, /* unrecognized method → no channel */
    CHAN_CMP_CHILDREN = 3, /* left OP right — simple binary comparison */
};

typedef struct {
    const char *name;  /* borrowed — points into arena */
    const char *value; /* borrowed — points into arena */
} chan_const_t;

typedef struct {
    chan_const_t items[CHAN_CONST_CAP];
    int count;
} chan_const_table_t;

/* ── String literal helpers ──────────────────────────────────────── */

static const char *unquote_string(CBMArena *a, const char *s) {
    if (!s) {
        return NULL;
    }
    size_t len = strlen(s);
    if (len < CBM_QUOTE_PAIR) {
        return NULL;
    }
    char first = s[0];
    char last = s[len - CBM_QUOTE_OFFSET];
    if ((first == '"' && last == '"') || (first == '\'' && last == '\'') ||
        (first == '`' && last == '`')) {
        return cbm_arena_strndup(a, s + CBM_QUOTE_OFFSET, len - CBM_QUOTE_PAIR);
    }
    return NULL;
}

/* Extract a literal channel name from an argument node.  Returns NULL if the
 * argument is not a plain string literal (caller can then try identifier
 * resolution via the constant table). */
static const char *literal_from_arg(CBMExtractCtx *ctx, TSNode arg) {
    const char *kind = ts_node_type(arg);
    if (strcmp(kind, "string") != 0 && strcmp(kind, "string_literal") != 0 &&
        strcmp(kind, "interpreted_string_literal") != 0 &&
        strcmp(kind, "raw_string_literal") != 0 && strcmp(kind, "string_content") != 0) {
        return NULL;
    }
    char *text = cbm_node_text(ctx->arena, arg, ctx->source);
    return unquote_string(ctx->arena, text);
}

/* Extract string literal from first named child (for nodes wrapping string content). */
static const char *literal_from_first_child(CBMExtractCtx *ctx, TSNode node) {
    uint32_t nc = ts_node_named_child_count(node);
    for (uint32_t i = 0; i < nc; i++) {
        TSNode child = ts_node_named_child(node, i);
        const char *val = literal_from_arg(ctx, child);
        if (val) {
            return val;
        }
    }
    return NULL;
}

/* `env.FOO`, `process.env.FOO` → "FOO".  A queue URL is configuration: the
 * literal differs per environment, the env key does not.  The key is therefore
 * the only name a producer in one repo and a consumer in another actually
 * share, so it is what the channel is called when the URL is not literal. */
static const char *js_env_key_from_node(CBMExtractCtx *ctx, TSNode node) {
    if (ts_node_is_null(node) || strcmp(ts_node_type(node), "member_expression") != 0) {
        return NULL;
    }
    TSNode object = ts_node_child_by_field_name(node, TS_FIELD("object"));
    TSNode property = ts_node_child_by_field_name(node, TS_FIELD("property"));
    if (ts_node_is_null(object) || ts_node_is_null(property)) {
        return NULL;
    }
    char *obj_text = cbm_node_text(ctx->arena, object, ctx->source);
    if (!obj_text || (strcmp(obj_text, "env") != 0 && strcmp(obj_text, "process.env") != 0 &&
                      strcmp(obj_text, "Deno.env") != 0)) {
        return NULL;
    }
    char *key = cbm_node_text(ctx->arena, property, ctx->source);
    return (key && key[0]) ? key : NULL;
}

/* ── Constant resolution table ──────────────────────────────────── */

/* Walk the whole tree once and collect `const IDENT = "value"` bindings so
 * later passes can resolve bare-identifier channel arguments.  Only scalar
 * string literals are tracked — template literals and expressions are left
 * unresolved.  This is a flat lookup; scope boundaries are ignored (a single
 * const table per file is sufficient for the common Socket.IO pattern). */
static void scan_string_consts_js(CBMExtractCtx *ctx, chan_const_table_t *tbl) {
    TSNodeStack stack;
    ts_nstack_init(&stack, ctx->arena, CHAN_STACK_CAP);
    ts_nstack_push(&stack, ctx->arena, ctx->root);

    while (stack.count > 0 && tbl->count < CHAN_CONST_CAP) {
        TSNode node = ts_nstack_pop(&stack);
        const char *kind = ts_node_type(node);

        if (strcmp(kind, "variable_declarator") == 0) {
            TSNode name_node = ts_node_child_by_field_name(node, TS_FIELD("name"));
            TSNode value_node = ts_node_child_by_field_name(node, TS_FIELD("value"));
            if (!ts_node_is_null(name_node) && !ts_node_is_null(value_node)) {
                const char *nk = ts_node_type(name_node);
                const char *vk = ts_node_type(value_node);
                if (strcmp(nk, "identifier") == 0 &&
                    (strcmp(vk, "string") == 0 || strcmp(vk, "string_literal") == 0)) {
                    char *name_text = cbm_node_text(ctx->arena, name_node, ctx->source);
                    char *value_text = cbm_node_text(ctx->arena, value_node, ctx->source);
                    const char *unq = unquote_string(ctx->arena, value_text);
                    if (name_text && unq) {
                        tbl->items[tbl->count].name = name_text;
                        tbl->items[tbl->count].value = unq;
                        tbl->count++;
                    }
                }
            }
        }

        /* `this.queueName = "all-processed.queue"` — a constructor field is how
         * a consumer class names the queue it reads.  Without this the name
         * argument never resolves to a literal and the queue has no listener. */
        if (strcmp(kind, "assignment_expression") == 0) {
            TSNode lhs = ts_node_child_by_field_name(node, TS_FIELD("left"));
            TSNode rhs = ts_node_child_by_field_name(node, TS_FIELD("right"));
            if (!ts_node_is_null(lhs) && !ts_node_is_null(rhs) &&
                strcmp(ts_node_type(lhs), "member_expression") == 0 &&
                (strcmp(ts_node_type(rhs), "string") == 0 ||
                 strcmp(ts_node_type(rhs), "string_literal") == 0)) {
                char *lhs_text = cbm_node_text(ctx->arena, lhs, ctx->source);
                char *rhs_text = cbm_node_text(ctx->arena, rhs, ctx->source);
                const char *unq_val = unquote_string(ctx->arena, rhs_text);
                if (lhs_text && unq_val && tbl->count < CHAN_CONST_CAP) {
                    tbl->items[tbl->count].name = lhs_text;
                    tbl->items[tbl->count].value = unq_val;
                    tbl->count++;
                }
            }
        }

        /* `constructor(private readonly topicArn = env.BUS_EVENTS_TOPIC_ARN)` and
         * `private readonly queueUrl = env.Q` — the adapter reads the env once, at
         * the declaration, and every call site afterwards says only
         * `this.topicArn`.  Without binding the field to its env key the queue the
         * whole adapter exists to address resolves to nothing. */
        if (strcmp(kind, "required_parameter") == 0 || strcmp(kind, "optional_parameter") == 0 ||
            strcmp(kind, "public_field_definition") == 0) {
            /* TS_FIELD expands to two arguments, so the field name cannot be
             * chosen with a conditional expression. */
            TSNode name_node;
            if (strcmp(kind, "public_field_definition") == 0) {
                name_node = ts_node_child_by_field_name(node, TS_FIELD("name"));
            } else {
                name_node = ts_node_child_by_field_name(node, TS_FIELD("pattern"));
            }
            TSNode value_node = ts_node_child_by_field_name(node, TS_FIELD("value"));
            const char *env_key = js_env_key_from_node(ctx, value_node);
            if (!ts_node_is_null(name_node) && env_key && tbl->count < CHAN_CONST_CAP) {
                char *field = cbm_node_text(ctx->arena, name_node, ctx->source);
                if (field && field[0]) {
                    tbl->items[tbl->count].name = cbm_arena_sprintf(ctx->arena, "this.%s", field);
                    tbl->items[tbl->count].value = env_key;
                    tbl->count++;
                }
            }
        }

        ts_nstack_push_children(&stack, ctx->arena, node);
    }
}

/* Python constant resolution: NAME = "value" (assignment node). */
/* Name of the class body an assignment sits in, or NULL at module level. */
/* Like py_enclosing_class_name, but does not stop at a method boundary: a
 * worker sets `self.queue_name` in __init__, and that field belongs to the
 * class even though the statement sits inside a function. */
static const char *py_owning_class_name(CBMExtractCtx *ctx, TSNode node) {
    TSNode parent = ts_node_parent(node);
    while (!ts_node_is_null(parent)) {
        if (strcmp(ts_node_type(parent), "class_definition") == 0) {
            TSNode name_node = ts_node_child_by_field_name(parent, TS_FIELD("name"));
            return ts_node_is_null(name_node) ? NULL
                                              : cbm_node_text(ctx->arena, name_node, ctx->source);
        }
        parent = ts_node_parent(parent);
    }
    return NULL;
}

static const char *py_enclosing_class_name(CBMExtractCtx *ctx, TSNode node) {
    TSNode parent = ts_node_parent(node);
    while (!ts_node_is_null(parent)) {
        const char *pk = ts_node_type(parent);
        if (strcmp(pk, "class_definition") == 0) {
            TSNode name_node = ts_node_child_by_field_name(parent, TS_FIELD("name"));
            if (ts_node_is_null(name_node)) {
                return NULL;
            }
            return cbm_node_text(ctx->arena, name_node, ctx->source);
        }
        if (strcmp(pk, "function_definition") == 0) {
            return NULL;
        }
        parent = ts_node_parent(parent);
    }
    return NULL;
}

static void scan_string_consts_python(CBMExtractCtx *ctx, chan_const_table_t *tbl) {
    TSNodeStack stack;
    ts_nstack_init(&stack, ctx->arena, CHAN_STACK_CAP);
    ts_nstack_push(&stack, ctx->arena, ctx->root);

    while (stack.count > 0 && tbl->count < CHAN_CONST_CAP) {
        TSNode node = ts_nstack_pop(&stack);
        const char *kind = ts_node_type(node);

        if (strcmp(kind, "assignment") == 0) {
            TSNode left = ts_node_child_by_field_name(node, TS_FIELD("left"));
            TSNode right = ts_node_child_by_field_name(node, TS_FIELD("right"));
            if (!ts_node_is_null(left) && !ts_node_is_null(right) &&
                strcmp(ts_node_type(left), "identifier") == 0 &&
                strcmp(ts_node_type(right), "string") == 0) {
                char *name = cbm_node_text(ctx->arena, left, ctx->source);
                const char *val = literal_from_arg(ctx, right);
                if (!val) {
                    val = literal_from_first_child(ctx, right);
                }
                if (name && val) {
                    tbl->items[tbl->count].name = name;
                    tbl->items[tbl->count].value = val;
                    tbl->count++;
                    /* `class Queues: MODERATION = "..."` is referenced as
                     * `Queues.MODERATION`; record that spelling too. */
                    const char *owner = py_enclosing_class_name(ctx, node);
                    if (owner && tbl->count < CHAN_CONST_CAP) {
                        char *qualified = cbm_arena_sprintf(ctx->arena, "%s.%s", owner, name);
                        if (qualified) {
                            tbl->items[tbl->count].name = qualified;
                            tbl->items[tbl->count].value = val;
                            tbl->count++;
                        }
                    }
                }
            }
        }

        uint32_t count = ts_node_child_count(node);
        for (int i = (int)count - SKIP_ONE; i >= 0; i--) {
            ts_nstack_push(&stack, ctx->arena, ts_node_child(node, (uint32_t)i));
        }
    }
}

/* Resolve an identifier against the constant table.  Returns NULL on miss. */
static const char *resolve_identifier(const chan_const_table_t *tbl, const char *name) {
    if (!name) {
        return NULL;
    }
    for (int i = 0; i < tbl->count; i++) {
        if (tbl->items[i].name && strcmp(tbl->items[i].name, name) == 0) {
            return tbl->items[i].value;
        }
    }
    return NULL;
}

/* ── Enclosing function detection ───────────────────────────────── */

static const char *enclosing_function_qn(CBMExtractCtx *ctx, TSNode node) {
    TSNode parent = ts_node_parent(node);
    while (!ts_node_is_null(parent)) {
        const char *pk = ts_node_type(parent);
        if (strcmp(pk, "function_declaration") == 0 || strcmp(pk, "method_definition") == 0 ||
            strcmp(pk, "arrow_function") == 0 || strcmp(pk, "function_expression") == 0 ||
            strcmp(pk, "function") == 0 || strcmp(pk, "method_signature") == 0 ||
            strcmp(pk, "function_definition") == 0 || strcmp(pk, "method_declaration") == 0 ||
            strcmp(pk, "function_item") == 0 || strcmp(pk, "def") == 0) {
            TSNode name_node = ts_node_child_by_field_name(parent, TS_FIELD("name"));
            if (!ts_node_is_null(name_node)) {
                char *name = cbm_node_text(ctx->arena, name_node, ctx->source);
                if (name && name[0]) {
                    return name;
                }
            }
            return NULL;
        }
        parent = ts_node_parent(parent);
    }
    return NULL;
}

/* ── Channel name extraction from arguments ──────────────────────── */

/* Try to extract a channel name from the first argument of a call.
 * Tries literal first, then identifier resolution via constant table. */
static const char *extract_channel_name(CBMExtractCtx *ctx, TSNode args,
                                        const chan_const_table_t *consts) {
    uint32_t arg_count = ts_node_named_child_count(args);
    if (arg_count == 0) {
        return NULL;
    }
    TSNode first = ts_node_named_child(args, 0);

    const char *channel_name = literal_from_arg(ctx, first);
    if (!channel_name) {
        channel_name = literal_from_first_child(ctx, first);
    }
    if (!channel_name && consts) {
        const char *kind = ts_node_type(first);
        /* member_expression covers `this.queueName`, recorded by the constant
         * scan above under its full text. */
        if (strcmp(kind, "identifier") == 0 || strcmp(kind, "member_expression") == 0) {
            char *ident = cbm_node_text(ctx->arena, first, ctx->source);
            channel_name = resolve_identifier(consts, ident);
        }
    }
    return channel_name;
}

/* ── AWS SDK v3 command channels ─────────────────────────────────── */

/* v3 gives the client exactly one verb: `client.send(new XxxCommand({...}))`.
 * The receiver is an opaque handle whose tail reads as "client" — which
 * classifies as socketio — and the first argument is a `new_expression`, not a
 * string, so the call resolved to no channel name and was dropped in silence.
 * The command CLASS is what pins transport and direction, the same way
 * `sendToQueue` pins amqplib.  Only messaging commands qualify: S3 and DynamoDB
 * ride the identical shape, and calling a bucket a channel would invent an edge
 * between every repo that reads it. */
static const struct {
    const char *command;
    const char *transport;
    CBMChannelDirection direction;
    const char *name_key;
} aws_v3_command_table[] = {
    {"SendMessageCommand", "sqs", CBM_CHANNEL_EMIT, "QueueUrl"},
    {"SendMessageBatchCommand", "sqs", CBM_CHANNEL_EMIT, "QueueUrl"},
    {"ReceiveMessageCommand", "sqs", CBM_CHANNEL_LISTEN, "QueueUrl"},
    {"PublishCommand", "sns", CBM_CHANNEL_EMIT, "TopicArn"},
    {"PublishBatchCommand", "sns", CBM_CHANNEL_EMIT, "TopicArn"},
    {"PutEventsCommand", "eventbridge", CBM_CHANNEL_EMIT, "EventBusName"},
    {NULL, NULL, CBM_CHANNEL_EMIT, NULL},
};

/* Value of `key` in an object literal, or 0 when the key is absent. */
static int js_object_value_for_key(CBMExtractCtx *ctx, TSNode object, const char *key,
                                   TSNode *out) {
    uint32_t n = ts_node_named_child_count(object);
    for (uint32_t i = 0; i < n; i++) {
        TSNode child = ts_node_named_child(object, i);
        if (strcmp(ts_node_type(child), "pair") != 0) {
            continue;
        }
        TSNode k = ts_node_child_by_field_name(child, TS_FIELD("key"));
        if (ts_node_is_null(k)) {
            continue;
        }
        char *k_text = cbm_node_text(ctx->arena, k, ctx->source);
        const char *unq = unquote_string(ctx->arena, k_text);
        const char *name = unq ? unq : k_text;
        if (name && strcmp(name, key) == 0) {
            TSNode v = ts_node_child_by_field_name(child, TS_FIELD("value"));
            if (ts_node_is_null(v)) {
                return 0;
            }
            *out = v;
            return 1;
        }
    }
    return 0;
}

/* Literal → module constant / env-bound field → env key. */
static const char *js_channel_name_from_value(CBMExtractCtx *ctx, TSNode value,
                                              const chan_const_table_t *consts) {
    const char *name = literal_from_arg(ctx, value);
    if (name) {
        return name;
    }
    const char *kind = ts_node_type(value);
    if (consts && (strcmp(kind, "identifier") == 0 || strcmp(kind, "member_expression") == 0)) {
        char *ident = cbm_node_text(ctx->arena, value, ctx->source);
        const char *resolved = resolve_identifier(consts, ident);
        if (resolved) {
            return resolved;
        }
    }
    return js_env_key_from_node(ctx, value);
}

/* 1 when the call is an AWS SDK v3 messaging command, with the channel filled. */
static int js_aws_v3_command_channel(CBMExtractCtx *ctx, TSNode call, const char *method,
                                     const chan_const_table_t *consts, const char **transport,
                                     CBMChannelDirection *direction, const char **name) {
    if (!method || strcmp(method, "send") != 0) {
        return 0;
    }
    TSNode args = ts_node_child_by_field_name(call, TS_FIELD("arguments"));
    if (ts_node_is_null(args) || ts_node_named_child_count(args) == 0) {
        return 0;
    }
    TSNode first = ts_node_named_child(args, 0);
    if (strcmp(ts_node_type(first), "new_expression") != 0) {
        return 0;
    }
    TSNode ctor = ts_node_child_by_field_name(first, TS_FIELD("constructor"));
    if (ts_node_is_null(ctor)) {
        return 0;
    }
    char *ctor_name = cbm_node_text(ctx->arena, ctor, ctx->source);
    if (!ctor_name) {
        return 0;
    }
    int idx = -1;
    for (int i = 0; aws_v3_command_table[i].command != NULL; i++) {
        if (strcmp(aws_v3_command_table[i].command, ctor_name) == 0) {
            idx = i;
            break;
        }
    }
    if (idx < 0) {
        return 0;
    }
    TSNode cargs = ts_node_child_by_field_name(first, TS_FIELD("arguments"));
    if (ts_node_is_null(cargs) || ts_node_named_child_count(cargs) == 0) {
        return 0;
    }
    TSNode payload = ts_node_named_child(cargs, 0);
    if (strcmp(ts_node_type(payload), "object") != 0) {
        return 0;
    }
    TSNode value;
    if (!js_object_value_for_key(ctx, payload, aws_v3_command_table[idx].name_key, &value)) {
        return 0;
    }
    const char *resolved = js_channel_name_from_value(ctx, value, consts);
    if (!resolved || !resolved[0]) {
        return 0;
    }
    *transport = aws_v3_command_table[idx].transport;
    *direction = aws_v3_command_table[idx].direction;
    *name = resolved;
    return 1;
}

/* ── Emit helper ─────────────────────────────────────────────────── */

static void push_channel(CBMExtractCtx *ctx, const char *channel_name, const char *transport,
                         CBMChannelDirection direction, TSNode call) {
    CBMChannel ch = {
        .channel_name = channel_name,
        .transport = transport,
        .enclosing_func_qn = enclosing_function_qn(ctx, call),
        .direction = direction,
    };
    cbm_channels_push(&ctx->result->channels, ctx->arena, ch);
}

/* The message-type namespace: channels routed by a discriminator field inside
 * the payload (or by the in-house bus port's event-name argument), not by a
 * queue or socket name.  Shared by the JS and Python extractors so producer
 * and consumer land on the same QN regardless of language. */
#define CHAN_MSGTYPE_TRANSPORT "message_type"

/* Case-sensitive suffix check on an already-isolated receiver tail. */
static bool tail_has_suffix(const char *tail, const char *suffix) {
    size_t tl = strlen(tail);
    size_t sl = strlen(suffix);
    return tl >= sl && strcmp(tail + tl - sl, suffix) == 0;
}

/* ══════════════════════════════════════════════════════════════════
 *  JS/TS/TSX — Socket.IO, EventEmitter, WebSocket, Kafka, RabbitMQ
 * ══════════════════════════════════════════════════════════════════ */

static bool js_is_emit_method(const char *name) {
    return name && strcmp(name, "emit") == 0;
}

static bool js_is_listen_method(const char *name) {
    return name && (strcmp(name, "on") == 0 || strcmp(name, "addListener") == 0 ||
                    strcmp(name, "once") == 0);
}

/* Classify receiver for Socket.IO / EventEmitter / WebSocket. */
static const char *js_classify_receiver_depth(CBMExtractCtx *ctx, TSNode object_node, int depth);

static const char *js_classify_receiver(CBMExtractCtx *ctx, TSNode object_node) {
    return js_classify_receiver_depth(ctx, object_node, 0);
}

static const char *js_classify_receiver_depth(CBMExtractCtx *ctx, TSNode object_node, int depth) {
    /* `io.to(room).emit(...)` is THE socket.io broadcast idiom, and the room
     * scoping puts a call between the handle and the emit: classified on the
     * text tail, the receiver reads as `to(room)` and matches nothing, so every
     * room-scoped broadcast was invisible while the direct `socket.emit` next
     * to it resolved.  A chained call inherits the classification of the handle
     * it was chained onto. */
    enum { JS_RECEIVER_CHAIN_MAX = 4 };
    if (depth < JS_RECEIVER_CHAIN_MAX && strcmp(ts_node_type(object_node), "call_expression") == 0) {
        TSNode fn = ts_node_child_by_field_name(object_node, TS_FIELD("function"));
        if (!ts_node_is_null(fn) && strcmp(ts_node_type(fn), "member_expression") == 0) {
            TSNode inner = ts_node_child_by_field_name(fn, TS_FIELD("object"));
            if (!ts_node_is_null(inner)) {
                return js_classify_receiver_depth(ctx, inner, depth + 1);
            }
        }
        return NULL;
    }
    char *text = cbm_node_text(ctx->arena, object_node, ctx->source);
    if (!text) {
        return NULL;
    }
    const char *tail = text;
    const char *dot = strrchr(tail, '.');
    if (dot) {
        tail = dot + SKIP_ONE;
    }
    /* Socket.IO */
    if (strcmp(tail, "socket") == 0 || strcmp(tail, "io") == 0 || strcmp(tail, "ws") == 0 ||
        strcmp(tail, "client") == 0 || strcmp(tail, "server") == 0) {
        return "socketio";
    }
    /* Node.js EventEmitter */
    if (strcmp(tail, "emitter") == 0 || strcmp(tail, "eventEmitter") == 0 ||
        strcmp(tail, "events") == 0 || strcmp(tail, "bus") == 0 || strcmp(tail, "eventBus") == 0 ||
        strcmp(tail, "pubsub") == 0) {
        return "event_emitter";
    }
    /* Kafka */
    if (strcmp(tail, "producer") == 0) {
        return "kafka";
    }
    if (strcmp(tail, "consumer") == 0) {
        return "kafka";
    }
    /* RabbitMQ / AMQP.  The receiver is either a raw amqplib channel handle or
     * a wrapper that owns one.  Matching only the exact text "channel" missed
     * both `conn.channel.sendToQueue(...)` and the common consumer shape where
     * the handle is a field (`this.queue.consume(...)`), so the LISTEN side of
     * every queue was invisible while the EMIT side resolved. */
    if (strcmp(tail, "channel") == 0 || strcmp(tail, "ch") == 0 ||
        strcmp(tail, "queue") == 0 || strcmp(tail, "rabbitmq") == 0 ||
        strcmp(tail, "amqp") == 0 || strcmp(tail, "broker") == 0 ||
        strcmp(tail, "mq") == 0) {
        return "rabbitmq";
    }
    /* In-house bus port (ports-and-adapters over SNS/SQS or similar): the
     * handle is named for its role — `publisher.publish('coins_changed', body)`,
     * `deps.publisher`, `busPublisher`.  The name argument is the envelope's
     * `event` discriminator, i.e. the message_type namespace, NOT a queue: the
     * consumer on the other side dispatches on `msg.event`, so this is the only
     * labelling under which producer and consumer share a QN. */
    if (strcmp(tail, "publisher") == 0 || tail_has_suffix(tail, "Publisher")) {
        return CHAN_MSGTYPE_TRANSPORT;
    }
    return NULL;
}

/* Detect Kafka/RabbitMQ specific send/subscribe patterns. */
static bool js_is_kafka_send(const char *method) {
    return method && (strcmp(method, "send") == 0 || strcmp(method, "sendBatch") == 0);
}

static bool js_is_kafka_listen(const char *method) {
    return method && (strcmp(method, "subscribe") == 0 || strcmp(method, "run") == 0);
}

static bool js_is_amqp_send(const char *method) {
    return method && (strcmp(method, "publish") == 0 || strcmp(method, "sendToQueue") == 0);
}

static bool js_is_amqp_listen(const char *method) {
    return method && (strcmp(method, "consume") == 0 || strcmp(method, "assertQueue") == 0);
}

/* ── Message-type discriminators ─────────────────────────────────
 *
 * A broker payload is routed by a field inside the message, not by the queue:
 * one queue carries every event and the consumer switches on `type`.  The queue
 * name alone therefore links two services but says nothing about which event
 * crosses; publisher and handler of a given event stay unconnected.  Both sides
 * are plain string literals, so we record them as channels on their own
 * transport and let the existing cross-repo channel matcher pair them. */

static bool is_msgtype_key(const char *key) {
    return key && (strcmp(key, "type") == 0 || strcmp(key, "event") == 0 ||
                   strcmp(key, "eventType") == 0 || strcmp(key, "event_type") == 0 ||
                   strcmp(key, "messageType") == 0 || strcmp(key, "message_type") == 0);
}

/* Strip quotes from a property key node's text (`"type"` and `type` both occur). */
static const char *pair_key_text(CBMExtractCtx *ctx, TSNode key_node) {
    char *raw = cbm_node_text(ctx->arena, key_node, ctx->source);
    if (!raw) {
        return NULL;
    }
    const char *unq = unquote_string(ctx->arena, raw);
    return unq ? unq : raw;
}

/* Walk a published call's arguments for `{ type: "dynamic_on_air", ... }`.
 * The object is usually nested inside JSON.stringify(...) and Buffer.from(...),
 * so this walks the whole argument subtree rather than the top level only. */
static void js_emit_message_types(CBMExtractCtx *ctx, TSNode args) {
    TSNodeStack stack;
    ts_nstack_init(&stack, ctx->arena, CHAN_STACK_CAP);
    ts_nstack_push(&stack, ctx->arena, args);

    while (stack.count > 0) {
        TSNode node = ts_nstack_pop(&stack);
        if (strcmp(ts_node_type(node), "pair") == 0) {
            TSNode key = ts_node_child_by_field_name(node, TS_FIELD("key"));
            TSNode val = ts_node_child_by_field_name(node, TS_FIELD("value"));
            if (!ts_node_is_null(key) && !ts_node_is_null(val) &&
                is_msgtype_key(pair_key_text(ctx, key))) {
                const char *type_name = literal_from_arg(ctx, val);
                if (type_name && type_name[0]) {
                    push_channel(ctx, type_name, CHAN_MSGTYPE_TRANSPORT, CBM_CHANNEL_EMIT, node);
                }
            }
        }
        ts_nstack_push_children(&stack, ctx->arena, node);
    }
}

/* `switch (type) { case "dynamic_on_air": ... }` — the handler side.  Only a
 * switch whose discriminant is named like a message-type field qualifies, so an
 * unrelated switch over a status enum does not manufacture channels. */
static void js_listen_message_types(CBMExtractCtx *ctx, TSNode sw) {
    TSNode disc = ts_node_child_by_field_name(sw, TS_FIELD("value"));
    if (ts_node_is_null(disc)) {
        return;
    }
    char *disc_text = cbm_node_text(ctx->arena, disc, ctx->source);
    if (!disc_text) {
        return;
    }
    /* The grammar hands back a parenthesized_expression, so the raw text is
     * "(type)"; strip the wrapper before comparing against the key names. */
    const char *tail = disc_text;
    while (*tail == '(' || *tail == ' ') {
        tail++;
    }
    char disc_bare[CHAN_IDENT_MAX];
    size_t di = 0;
    while (tail[di] && tail[di] != ')' && tail[di] != ' ' && di < sizeof(disc_bare) - 1) {
        disc_bare[di] = tail[di];
        di++;
    }
    disc_bare[di] = '\0';
    tail = disc_bare;
    const char *dot = strrchr(tail, '.');
    if (dot) {
        tail = dot + SKIP_ONE;
    }
    if (!is_msgtype_key(tail)) {
        return;
    }
    TSNode body = ts_node_child_by_field_name(sw, TS_FIELD("body"));
    if (ts_node_is_null(body)) {
        return;
    }
    uint32_t nc = ts_node_named_child_count(body);
    for (uint32_t i = 0; i < nc; i++) {
        TSNode kase = ts_node_named_child(body, i);
        if (strcmp(ts_node_type(kase), "switch_case") != 0) {
            continue;
        }
        TSNode label = ts_node_child_by_field_name(kase, TS_FIELD("value"));
        if (ts_node_is_null(label)) {
            continue;
        }
        const char *type_name = literal_from_arg(ctx, label);
        if (type_name && type_name[0]) {
            push_channel(ctx, type_name, CHAN_MSGTYPE_TRANSPORT, CBM_CHANNEL_LISTEN, kase);
        }
    }
}

static void js_process_call(CBMExtractCtx *ctx, TSNode call, const chan_const_table_t *consts) {
    TSNode func = ts_node_child_by_field_name(call, TS_FIELD("function"));
    if (ts_node_is_null(func) || strcmp(ts_node_type(func), "member_expression") != 0) {
        return;
    }
    TSNode object = ts_node_child_by_field_name(func, TS_FIELD("object"));
    TSNode property = ts_node_child_by_field_name(func, TS_FIELD("property"));
    if (ts_node_is_null(object) || ts_node_is_null(property)) {
        return;
    }

    char *method = cbm_node_text(ctx->arena, property, ctx->source);

    /* Checked before the receiver: an AWS v3 handle is named `client`, which
     * classifies as socketio, so asking the receiver first answers wrongly. */
    const char *aws_transport = NULL;
    const char *aws_name = NULL;
    CBMChannelDirection aws_direction = CBM_CHANNEL_EMIT;
    if (js_aws_v3_command_channel(ctx, call, method, consts, &aws_transport, &aws_direction,
                                  &aws_name)) {
        push_channel(ctx, aws_name, aws_transport, aws_direction, call);
        return;
    }

    const char *transport = js_classify_receiver(ctx, object);
    /* sendToQueue/assertQueue are amqplib-exclusive method names: the method
     * alone pins the transport, so a wrapper whose name we cannot classify
     * (queueFactory.rabbitmq, an injected client) still yields a channel. */
    if (!transport && method &&
        (strcmp(method, "sendToQueue") == 0 || strcmp(method, "assertQueue") == 0)) {
        transport = "rabbitmq";
    }
    if (!transport) {
        return;
    }

    CBMChannelDirection direction;
    if (strcmp(transport, "kafka") == 0) {
        if (js_is_kafka_send(method)) {
            direction = CBM_CHANNEL_EMIT;
        } else if (js_is_kafka_listen(method)) {
            direction = CBM_CHANNEL_LISTEN;
        } else {
            return;
        }
    } else if (strcmp(transport, "rabbitmq") == 0) {
        if (js_is_amqp_send(method)) {
            direction = CBM_CHANNEL_EMIT;
        } else if (js_is_amqp_listen(method)) {
            direction = CBM_CHANNEL_LISTEN;
        } else {
            return;
        }
    } else if (strcmp(transport, CHAN_MSGTYPE_TRANSPORT) == 0) {
        /* In-house bus publisher handle: only its two port verbs qualify. */
        if (method && strcmp(method, "publish") == 0) {
            direction = CBM_CHANNEL_EMIT;
        } else if (method && strcmp(method, "subscribe") == 0) {
            direction = CBM_CHANNEL_LISTEN;
        } else {
            return;
        }
    } else {
        /* socketio / event_emitter */
        if (js_is_emit_method(method)) {
            direction = CBM_CHANNEL_EMIT;
        } else if (js_is_listen_method(method)) {
            direction = CBM_CHANNEL_LISTEN;
        } else if (strcmp(transport, "event_emitter") == 0 && method &&
                   (strcmp(method, "publish") == 0 || strcmp(method, "subscribe") == 0)) {
            /* A receiver named `bus`/`eventBus`/`pubsub` speaking publish/
             * subscribe is not Node's EventEmitter — it is the in-house bus
             * port, and the name argument is the envelope's event
             * discriminator.  Same namespace as the consumer's `switch
             * (msg.event)`, so re-label instead of dropping the call. */
            transport = CHAN_MSGTYPE_TRANSPORT;
            direction = strcmp(method, "publish") == 0 ? CBM_CHANNEL_EMIT : CBM_CHANNEL_LISTEN;
        } else {
            return;
        }
    }

    TSNode args = ts_node_child_by_field_name(call, TS_FIELD("arguments"));
    if (ts_node_is_null(args)) {
        return;
    }
    /* The discriminator travels with the payload, so it is recorded even when
     * the queue name itself stays unresolved (config-driven or computed). */
    const char *channel_name = extract_channel_name(ctx, args, consts);
    if (direction == CBM_CHANNEL_EMIT &&
        (strcmp(transport, "rabbitmq") == 0 || strcmp(transport, "kafka") == 0 ||
         /* A gateway broadcasts one socket event carrying a typed envelope
          * (`emit("message", { type, payload })`).  The event name says only
          * "this is a message"; the `type` is what the client listens for, so
          * without it the gateway records no wire name a consumer could match. */
         (strcmp(transport, "socketio") == 0 && channel_name &&
          strcmp(channel_name, "message") == 0))) {
        js_emit_message_types(ctx, args);
    }
    if (!channel_name) {
        return;
    }
    push_channel(ctx, channel_name, transport, direction, call);
}

static void extract_channels_js(CBMExtractCtx *ctx) {
    chan_const_table_t consts = {0};
    scan_string_consts_js(ctx, &consts);

    /* Second pass: walk the tree looking for call_expression nodes. */
    TSNodeStack stack;
    ts_nstack_init(&stack, ctx->arena, CHAN_STACK_CAP);
    ts_nstack_push(&stack, ctx->arena, ctx->root);

    while (stack.count > 0) {
        TSNode node = ts_nstack_pop(&stack);
        if (strcmp(ts_node_type(node), "call_expression") == 0) {
            js_process_call(ctx, node, &consts);
        } else if (strcmp(ts_node_type(node), "switch_statement") == 0) {
            js_listen_message_types(ctx, node);
        }
        ts_nstack_push_children(&stack, ctx->arena, node);
    }
}

/* ══════════════════════════════════════════════════════════════════
 *  Python — python-socketio, Django Channels, FastAPI WebSocket, Kafka
 * ══════════════════════════════════════════════════════════════════ */

static const char *py_classify_receiver(CBMExtractCtx *ctx, TSNode object_node) {
    char *text = cbm_node_text(ctx->arena, object_node, ctx->source);
    if (!text) {
        return NULL;
    }
    const char *tail = text;
    const char *dot = strrchr(tail, '.');
    if (dot) {
        tail = dot + SKIP_ONE;
    }
    /* python-socketio */
    if (strcmp(tail, "sio") == 0 || strcmp(tail, "socketio") == 0 || strcmp(tail, "socket") == 0) {
        return "socketio";
    }
    /* Django Channels */
    if (strcmp(tail, "channel_layer") == 0) {
        return "django_channels";
    }
    /* FastAPI/Starlette WebSocket */
    if (strcmp(tail, "websocket") == 0 || strcmp(tail, "ws") == 0) {
        return "websocket";
    }
    /* kafka-python */
    if (strcmp(tail, "producer") == 0) {
        return "kafka";
    }
    if (strcmp(tail, "consumer") == 0) {
        return "kafka";
    }
    /* RabbitMQ: aio-pika/pika wrappers are named for what they wrap. */
    if (strstr(tail, "rabbitmq") != NULL || strstr(tail, "amqp") != NULL ||
        strcmp(tail, "broker") == 0 || strcmp(tail, "_broker") == 0 ||
        strcmp(tail, "queue_client") == 0 || strcmp(tail, "exchange") == 0 ||
        strcmp(tail, "queue") == 0 || strcmp(tail, "channel") == 0) {
        return "rabbitmq";
    }
    /* Redis pub/sub */
    if (strstr(tail, "redis") != NULL || strcmp(tail, "pubsub") == 0) {
        return "redis";
    }
    /* boto3 */
    if (strcmp(tail, "sns") == 0 || strcmp(tail, "sns_client") == 0) {
        return "sns";
    }
    if (strcmp(tail, "sqs") == 0 || strcmp(tail, "sqs_client") == 0) {
        return "sqs";
    }
    /* An in-house bus port: the transport is hidden, the topology is not. */
    if (tail_has_suffix(tail, "publisher") || tail_has_suffix(tail, "Publisher") ||
        strcmp(tail, "bus") == 0 || strcmp(tail, "_bus") == 0) {
        return "bus";
    }
    return NULL;
}

/* Table-driven Python method→direction classification.
 * NULL transport matches any transport not matched by earlier rows. */
static const struct {
    const char *transport; /* NULL = wildcard (socketio fallback) */
    const char *method;
    int direction;
} py_method_table[] = {
    {"kafka", "send", CBM_CHANNEL_EMIT},
    {"kafka", "produce", CBM_CHANNEL_EMIT},
    {"kafka", "subscribe", CBM_CHANNEL_LISTEN},
    {"kafka", "poll", CBM_CHANNEL_LISTEN},
    {"django_channels", "send", CBM_CHANNEL_EMIT},
    {"django_channels", "group_send", CBM_CHANNEL_EMIT},
    {"django_channels", "receive", CBM_CHANNEL_LISTEN},
    {"django_channels", "group_add", CBM_CHANNEL_LISTEN},
    {"websocket", "send", CBM_CHANNEL_EMIT},
    {"websocket", "send_text", CBM_CHANNEL_EMIT},
    {"websocket", "send_json", CBM_CHANNEL_EMIT},
    {"websocket", "send_bytes", CBM_CHANNEL_EMIT},
    {"websocket", "receive", CBM_CHANNEL_LISTEN},
    {"websocket", "receive_text", CBM_CHANNEL_LISTEN},
    {"websocket", "receive_json", CBM_CHANNEL_LISTEN},
    {"websocket", "receive_bytes", CBM_CHANNEL_LISTEN},
    {"rabbitmq", "publish", CBM_CHANNEL_EMIT},
    {"rabbitmq", "basic_publish", CBM_CHANNEL_EMIT},
    {"rabbitmq", "consume", CBM_CHANNEL_LISTEN},
    {"rabbitmq", "basic_consume", CBM_CHANNEL_LISTEN},
    {"rabbitmq", "start_consuming", CBM_CHANNEL_LISTEN},
    {"redis", "publish", CBM_CHANNEL_EMIT},
    {"redis", "subscribe", CBM_CHANNEL_LISTEN},
    {"redis", "psubscribe", CBM_CHANNEL_LISTEN},
    {"sns", "publish", CBM_CHANNEL_EMIT},
    {"sqs", "send_message", CBM_CHANNEL_EMIT},
    {"sqs", "receive_message", CBM_CHANNEL_LISTEN},
    {"bus", "publish", CBM_CHANNEL_EMIT},
    {"bus", "subscribe", CBM_CHANNEL_LISTEN},
    {NULL, "emit", CBM_CHANNEL_EMIT},
    {NULL, "send", CBM_CHANNEL_EMIT},
    {NULL, "on", CBM_CHANNEL_LISTEN},
    {NULL, NULL, CHAN_DIR_UNKNOWN},
};

static int py_classify_direction(const char *transport, const char *method) {
    for (int i = 0; py_method_table[i].method != NULL; i++) {
        const char *t = py_method_table[i].transport;
        if (t && strcmp(t, transport) != 0) {
            continue;
        }
        if (strcmp(py_method_table[i].method, method) == 0) {
            return py_method_table[i].direction;
        }
    }
    return CHAN_DIR_UNKNOWN;
}

/* Keyword arguments that name a channel, most specific first: `routing_key`
 * is what a consumer binds to, `exchange` only the broker it binds through. */
static bool py_is_channel_kwarg(const char *key) {
    static const char *keys[] = {"routing_key", "queue_name", "queue",  "topic",
                                 "channel",     "event",      "subject", "exchange",
                                 "QueueUrl",    "TopicArn",   NULL};
    for (int i = 0; keys[i]; i++) {
        if (strcmp(key, keys[i]) == 0) {
            return true;
        }
    }
    return false;
}

/* Resolve a channel-naming expression: literal, then the file's constant table,
 * then the dotted source text.  `Exchanges.SENTIMENT_ANALYSIS` is defined in
 * another file, so the text is all we have — and it is enough to match the
 * producer against the consumer that names the same constant. */
/* True when `value` is `self.<name>` and the class that encloses it defines a
 * method called <name>: the argument is a bound callback, not a queue. */
static bool py_self_attr_is_method(CBMExtractCtx *ctx, TSNode value) {
    if (strcmp(ts_node_type(value), "attribute") != 0) {
        return false;
    }
    TSNode object = ts_node_child_by_field_name(value, TS_FIELD("object"));
    TSNode attr = ts_node_child_by_field_name(value, TS_FIELD("attribute"));
    if (ts_node_is_null(object) || ts_node_is_null(attr)) {
        return false;
    }
    char *object_text = cbm_node_text(ctx->arena, object, ctx->source);
    if (!object_text || strcmp(object_text, "self") != 0) {
        return false;
    }
    char *attr_text = cbm_node_text(ctx->arena, attr, ctx->source);
    if (!attr_text || !attr_text[0]) {
        return false;
    }
    TSNode cls = ts_node_parent(value);
    while (!ts_node_is_null(cls) && strcmp(ts_node_type(cls), "class_definition") != 0) {
        cls = ts_node_parent(cls);
    }
    if (ts_node_is_null(cls)) {
        return false;
    }
    TSNode body = ts_node_child_by_field_name(cls, TS_FIELD("body"));
    if (ts_node_is_null(body)) {
        return false;
    }
    uint32_t n = ts_node_named_child_count(body);
    for (uint32_t i = 0; i < n; i++) {
        TSNode stmt = ts_node_named_child(body, i);
        if (strcmp(ts_node_type(stmt), "decorated_definition") == 0) {
            stmt = ts_node_child_by_field_name(stmt, TS_FIELD("definition"));
            if (ts_node_is_null(stmt)) {
                continue;
            }
        }
        if (strcmp(ts_node_type(stmt), "function_definition") != 0) {
            continue;
        }
        TSNode name = ts_node_child_by_field_name(stmt, TS_FIELD("name"));
        if (ts_node_is_null(name)) {
            continue;
        }
        char *name_text = cbm_node_text(ctx->arena, name, ctx->source);
        if (name_text && strcmp(name_text, attr_text) == 0) {
            return true;
        }
    }
    return false;
}

static const char *py_value_as_channel(CBMExtractCtx *ctx, TSNode value,
                                       const chan_const_table_t *consts) {
    const char *name = literal_from_arg(ctx, value);
    if (!name) {
        name = literal_from_first_child(ctx, value);
    }
    if (name) {
        return name;
    }
    const char *kind = ts_node_type(value);
    if (strcmp(kind, "identifier") != 0 && strcmp(kind, "attribute") != 0) {
        return NULL;
    }
    char *text = cbm_node_text(ctx->arena, value, ctx->source);
    if (!text || !text[0]) {
        return NULL;
    }
    const char *resolved = resolve_identifier(consts, text);
    if (resolved) {
        return resolved;
    }
    const char *dot = strrchr(text, '.');
    if (dot) {
        resolved = resolve_identifier(consts, dot + SKIP_ONE);
        if (resolved) {
            return resolved;
        }
    }
    /* A bare local (`queue_name`) carries no information; a dotted constant
     * reference does. */
    return dot ? text : NULL;
}

/* Emit one channel per channel-naming keyword argument.  Returns how many. */
static int py_emit_kwarg_channels(CBMExtractCtx *ctx, TSNode args, const char *transport,
                                  CBMChannelDirection direction,
                                  const chan_const_table_t *consts, TSNode call) {
    int emitted = 0;
    uint32_t n = ts_node_named_child_count(args);
    for (uint32_t i = 0; i < n; i++) {
        TSNode arg = ts_node_named_child(args, i);
        if (strcmp(ts_node_type(arg), "keyword_argument") != 0) {
            continue;
        }
        TSNode key = ts_node_child_by_field_name(arg, TS_FIELD("name"));
        TSNode value = ts_node_child_by_field_name(arg, TS_FIELD("value"));
        if (ts_node_is_null(key) || ts_node_is_null(value)) {
            continue;
        }
        char *key_text = cbm_node_text(ctx->arena, key, ctx->source);
        if (!key_text || !py_is_channel_kwarg(key_text)) {
            continue;
        }
        const char *name = py_value_as_channel(ctx, value, consts);
        if (!name) {
            continue;
        }
        push_channel(ctx, name, transport, direction, call);
        emitted++;
    }
    return emitted;
}

static void py_process_call(CBMExtractCtx *ctx, TSNode call, const chan_const_table_t *consts) {
    /* Python call: attribute { object, attribute }, argument_list */
    TSNode func = ts_node_child_by_field_name(call, TS_FIELD("function"));
    if (ts_node_is_null(func)) {
        return;
    }
    const char *fk = ts_node_type(func);
    if (strcmp(fk, "attribute") != 0) {
        return;
    }
    TSNode object = ts_node_child_by_field_name(func, TS_FIELD("object"));
    TSNode attr = ts_node_child_by_field_name(func, TS_FIELD("attribute"));
    if (ts_node_is_null(object) || ts_node_is_null(attr)) {
        return;
    }

    char *method = cbm_node_text(ctx->arena, attr, ctx->source);
    const char *transport = py_classify_receiver(ctx, object);
    if (!method) {
        return;
    }
    /* An unrecognised receiver still names a broker when the method only makes
     * sense on one.  Deliberately narrow: `send_message` is left out because
     * plenty of non-broker services have one. */
    if (!transport && (strcmp(method, "publish") == 0 || strcmp(method, "basic_publish") == 0 ||
                       strcmp(method, "consume") == 0 || strcmp(method, "basic_consume") == 0)) {
        transport = "rabbitmq";
    }
    if (!transport) {
        return;
    }

    int dir = py_classify_direction(transport, method);
    if (dir == CHAN_DIR_UNKNOWN) {
        return;
    }
    CBMChannelDirection direction = (CBMChannelDirection)dir;

    /* The in-house bus port routes by the envelope's `event` field —
     * `bus.publish("mini_trendings", body)` names a message type, not a
     * queue.  Store it under the shared message_type namespace so the QN
     * matches the JS side of the same pipe (`publisher.publish(...)` producers
     * and `switch (msg.event)` consumers); a "bus" label of its own would
     * split one logical channel into two QNs the cross-repo matcher can never
     * pair. */
    if (strcmp(transport, "bus") == 0) {
        transport = CHAN_MSGTYPE_TRANSPORT;
    }

    TSNode args = ts_node_child_by_field_name(call, TS_FIELD("arguments"));
    if (ts_node_is_null(args)) {
        return;
    }
    if (py_emit_kwarg_channels(ctx, args, transport, direction, consts, call) > 0) {
        return;
    }
    const char *channel_name = extract_channel_name(ctx, args, consts);
    if (!channel_name && ts_node_named_child_count(args) > 0) {
        /* `client.consume(self.queue_name, handler)` — the queue arrives as a
         * field, positionally.  Keeping the dotted spelling is what lets the
         * project-wide pass bind it to the literal the subclass configured;
         * dropped here, the consume site has no channel at all. */
        TSNode first = ts_node_named_child(args, 0);
        if (!py_self_attr_is_method(ctx, first)) {
            channel_name = py_value_as_channel(ctx, first, consts);
        }
    }
    if (!channel_name) {
        return;
    }
    push_channel(ctx, channel_name, transport, direction, call);
}

/* Detect Python decorator-based listeners: @sio.on("event") / @sio.event */
static void py_process_decorator(CBMExtractCtx *ctx, TSNode decorator,
                                 const chan_const_table_t *consts) {
    /* decorator: @expression or @call(args) */
    uint32_t nc = ts_node_named_child_count(decorator);
    if (nc == 0) {
        return;
    }
    TSNode expr = ts_node_named_child(decorator, 0);
    const char *ek = ts_node_type(expr);

    /* @sio.on("event") → call node wrapping attribute access */
    if (strcmp(ek, "call") == 0) {
        TSNode func = ts_node_child_by_field_name(expr, TS_FIELD("function"));
        if (ts_node_is_null(func) || strcmp(ts_node_type(func), "attribute") != 0) {
            return;
        }
        TSNode object = ts_node_child_by_field_name(func, TS_FIELD("object"));
        TSNode attr = ts_node_child_by_field_name(func, TS_FIELD("attribute"));
        if (ts_node_is_null(object) || ts_node_is_null(attr)) {
            return;
        }
        char *method = cbm_node_text(ctx->arena, attr, ctx->source);
        if (!method || strcmp(method, "on") != 0) {
            return;
        }
        const char *transport = py_classify_receiver(ctx, object);
        if (!transport) {
            return;
        }
        /* Same normalization as py_process_call: a bus-port listener names a
         * message type, not a queue. */
        if (strcmp(transport, "bus") == 0) {
            transport = CHAN_MSGTYPE_TRANSPORT;
        }
        TSNode args = ts_node_child_by_field_name(expr, TS_FIELD("arguments"));
        if (ts_node_is_null(args)) {
            return;
        }
        const char *channel_name = extract_channel_name(ctx, args, consts);
        if (!channel_name) {
            return;
        }
        push_channel(ctx, channel_name, transport, CBM_CHANNEL_LISTEN, decorator);
    }
}

/* ── Python message-type consumers ───────────────────────────────
 *
 * The Python bus consumers dispatch with equality, not a registry call:
 *
 *     if msg.event != "new_comment":
 *         return
 *     ...
 *     elif msg.event == "comment_moderated":
 *
 * This is the Python mirror of the JS `switch (msg.event)` handler — the
 * only place the handled event's name appears at all.  Both the `==`
 * dispatch and the `!=` early-return guard identify the event the enclosing
 * handler consumes.
 *
 * Unlike the JS switch heuristic this deliberately EXCLUDES the bare field
 * name `type`: `x.type == "assignment"` is ubiquitous in non-broker Python
 * (AST tooling, enums, ORMs) and would fabricate channels wholesale.  The
 * bus port's field is `event` (shared/bus/ports.py InboundMessage.event);
 * the other spellings cover the same discriminator in snake/camel form. */
static bool py_is_event_field(const char *key) {
    return key && (strcmp(key, "event") == 0 || strcmp(key, "event_type") == 0 ||
                   strcmp(key, "eventType") == 0 || strcmp(key, "message_type") == 0 ||
                   strcmp(key, "messageType") == 0);
}

/* One side of the comparison must be an attribute whose final segment is an
 * event field; returns its text validity, not the value. */
static bool py_node_is_event_attribute(CBMExtractCtx *ctx, TSNode node) {
    if (strcmp(ts_node_type(node), "attribute") != 0) {
        return false;
    }
    TSNode attr = ts_node_child_by_field_name(node, TS_FIELD("attribute"));
    if (ts_node_is_null(attr)) {
        return false;
    }
    char *name = cbm_node_text(ctx->arena, attr, ctx->source);
    return py_is_event_field(name);
}

static void py_listen_message_types(CBMExtractCtx *ctx, TSNode cmp) {
    /* Simple binary comparison only: left OP right.  Chained comparisons
     * (`a == b == c`) never carry this dispatch shape. */
    if (ts_node_child_count(cmp) != CHAN_CMP_CHILDREN) {
        return;
    }
    TSNode op = ts_node_child(cmp, SKIP_ONE);
    const char *op_kind = ts_node_type(op);
    if (strcmp(op_kind, "==") != 0 && strcmp(op_kind, "!=") != 0) {
        return;
    }
    TSNode left = ts_node_child(cmp, 0);
    TSNode right = ts_node_child(cmp, PAIR_LEN);

    /* Accept both operand orders; the literal side names the channel. */
    TSNode lit_node;
    if (py_node_is_event_attribute(ctx, left)) {
        lit_node = right;
    } else if (py_node_is_event_attribute(ctx, right)) {
        lit_node = left;
    } else {
        return;
    }
    const char *type_name = literal_from_arg(ctx, lit_node);
    if (!type_name) {
        type_name = literal_from_first_child(ctx, lit_node);
    }
    if (type_name && type_name[0]) {
        push_channel(ctx, type_name, CHAN_MSGTYPE_TRANSPORT, CBM_CHANNEL_LISTEN, cmp);
    }
}

/* Hand the file's `Class.ATTR = "literal"` bindings to the pipeline.  A queue
 * named by such a constant is published in one file and consumed in another,
 * and the constant is declared in a third; resolved only within a file, the
 * producer and the consumer of one queue never carry the same name, and the
 * edge between them cannot be drawn at all. */
static void publish_symbol_bindings(CBMExtractCtx *ctx, const chan_const_table_t *tbl) {
    for (int i = 0; i < tbl->count; i++) {
        const char *name = tbl->items[i].name;
        const char *value = tbl->items[i].value;
        if (!name || !value || !value[0] || !strchr(name, '.')) {
            continue;
        }
        CBMStringRef sr = {0};
        sr.value = value;
        sr.key_path = name;
        sr.kind = CBM_STRREF_SYMBOL;
        cbm_stringref_push(&ctx->result->string_refs, ctx->arena, sr);
    }
}

/* Publish `class W: queue_name = Queues.MODERATION` as a binding of the dotted
 * name `W.queue_name`.  A worker framework declares the consume loop once in a
 * base class (`self.channel.basic_consume(queue=self.queue_name)`) and leaves
 * the queue to a subclass field; read one file at a time, every worker built
 * that way is a producer with no consumer, which reads as a broken pipeline
 * rather than as a name the file cannot see. */
static void publish_class_attr_bindings(CBMExtractCtx *ctx) {
    TSNodeStack stack;
    ts_nstack_init(&stack, ctx->arena, CHAN_STACK_CAP);
    ts_nstack_push(&stack, ctx->arena, ctx->root);

    while (stack.count > 0) {
        TSNode node = ts_nstack_pop(&stack);
        if (strcmp(ts_node_type(node), "assignment") == 0) {
            TSNode left = ts_node_child_by_field_name(node, TS_FIELD("left"));
            TSNode right = ts_node_child_by_field_name(node, TS_FIELD("right"));
            const char *rk = ts_node_is_null(right) ? "" : ts_node_type(right);
            const char *lk = ts_node_is_null(left) ? "" : ts_node_type(left);
            /* `self.queue_name = Queues.MODERATION` in __init__ is the shape a
             * worker actually uses; a bare class-body assignment is the other. */
            TSNode target = left;
            bool self_attr = false;
            if (strcmp(lk, "attribute") == 0) {
                TSNode obj = ts_node_child_by_field_name(left, TS_FIELD("object"));
                TSNode att = ts_node_child_by_field_name(left, TS_FIELD("attribute"));
                char *obj_text = ts_node_is_null(obj) ? NULL : cbm_node_text(ctx->arena, obj, ctx->source);
                if (obj_text && strcmp(obj_text, "self") == 0 && !ts_node_is_null(att)) {
                    target = att;
                    self_attr = true;
                }
            }
            if ((strcmp(lk, "identifier") == 0 || self_attr) &&
                (strcmp(rk, "identifier") == 0 || strcmp(rk, "attribute") == 0)) {
                char *attr = cbm_node_text(ctx->arena, target, ctx->source);
                const char *owner = self_attr ? py_owning_class_name(ctx, node)
                                              : py_enclosing_class_name(ctx, node);
                char *value = cbm_node_text(ctx->arena, right, ctx->source);
                if (attr && owner && value && value[0] && py_is_channel_kwarg(attr)) {
                    CBMStringRef sr = {0};
                    sr.value = value;
                    sr.key_path = cbm_arena_sprintf(ctx->arena, "%s.%s", owner, attr);
                    sr.kind = CBM_STRREF_SYMBOL;
                    if (sr.key_path) {
                        cbm_stringref_push(&ctx->result->string_refs, ctx->arena, sr);
                    }
                }
            }
        }
        uint32_t count = ts_node_child_count(node);
        for (int i = (int)count - SKIP_ONE; i >= 0; i--) {
            ts_nstack_push(&stack, ctx->arena, ts_node_child(node, (uint32_t)i));
        }
    }
}

static void extract_channels_python(CBMExtractCtx *ctx) {
    chan_const_table_t consts = {0};
    scan_string_consts_python(ctx, &consts);
    publish_symbol_bindings(ctx, &consts);
    publish_class_attr_bindings(ctx);

    TSNodeStack stack;
    ts_nstack_init(&stack, ctx->arena, CHAN_STACK_CAP);
    ts_nstack_push(&stack, ctx->arena, ctx->root);

    while (stack.count > 0) {
        TSNode node = ts_nstack_pop(&stack);
        const char *kind = ts_node_type(node);
        if (strcmp(kind, "call") == 0) {
            py_process_call(ctx, node, &consts);
        } else if (strcmp(kind, "decorator") == 0) {
            py_process_decorator(ctx, node, &consts);
        } else if (strcmp(kind, "comparison_operator") == 0) {
            py_listen_message_types(ctx, node);
        }
        uint32_t count = ts_node_child_count(node);
        for (int i = (int)count - SKIP_ONE; i >= 0; i--) {
            ts_nstack_push(&stack, ctx->arena, ts_node_child(node, (uint32_t)i));
        }
    }
}

/* ══════════════════════════════════════════════════════════════════
 *  Go — gorilla/nhooyr websocket (WriteMessage/ReadMessage)
 * ══════════════════════════════════════════════════════════════════ */

static void go_process_call(CBMExtractCtx *ctx, TSNode call) {
    TSNode func = ts_node_child_by_field_name(call, TS_FIELD("function"));
    if (ts_node_is_null(func)) {
        return;
    }
    const char *fk = ts_node_type(func);
    if (strcmp(fk, "selector_expression") != 0) {
        return;
    }
    TSNode field = ts_node_child_by_field_name(func, TS_FIELD("field"));
    TSNode operand = ts_node_child_by_field_name(func, TS_FIELD("operand"));
    if (ts_node_is_null(field) || ts_node_is_null(operand)) {
        return;
    }

    char *method = cbm_node_text(ctx->arena, field, ctx->source);
    if (!method) {
        return;
    }

    /* gorilla/nhooyr websocket patterns */
    CBMChannelDirection direction;
    if (strcmp(method, "WriteMessage") == 0 || strcmp(method, "WriteJSON") == 0 ||
        strcmp(method, "Write") == 0) {
        direction = CBM_CHANNEL_EMIT;
    } else if (strcmp(method, "ReadMessage") == 0 || strcmp(method, "ReadJSON") == 0 ||
               strcmp(method, "Read") == 0) {
        direction = CBM_CHANNEL_LISTEN;
    } else {
        return;
    }

    /* Verify receiver looks like a websocket connection */
    char *recv = cbm_node_text(ctx->arena, operand, ctx->source);
    if (!recv) {
        return;
    }
    const char *tail = recv;
    const char *dot = strrchr(tail, '.');
    if (dot) {
        tail = dot + SKIP_ONE;
    }
    if (strcmp(tail, "conn") != 0 && strcmp(tail, "wsConn") != 0 && strcmp(tail, "ws") != 0 &&
        strcmp(tail, "c") != 0 && strcmp(tail, "Conn") != 0 && strcmp(tail, "connection") != 0) {
        return;
    }

    /* Go WebSocket uses connection-level send/receive, not named channels.
     * Use the enclosing function name as a pseudo-channel for cross-repo matching. */
    const char *func_name = enclosing_function_qn(ctx, call);
    const char *channel_name = func_name ? func_name : "(websocket)";
    push_channel(ctx, channel_name, "websocket", direction, call);
}

static void extract_channels_go(CBMExtractCtx *ctx) {
    TSNodeStack stack;
    ts_nstack_init(&stack, ctx->arena, CHAN_STACK_CAP);
    ts_nstack_push(&stack, ctx->arena, ctx->root);

    while (stack.count > 0) {
        TSNode node = ts_nstack_pop(&stack);
        if (strcmp(ts_node_type(node), "call_expression") == 0) {
            go_process_call(ctx, node);
        }
        uint32_t count = ts_node_child_count(node);
        for (int i = (int)count - SKIP_ONE; i >= 0; i--) {
            ts_nstack_push(&stack, ctx->arena, ts_node_child(node, (uint32_t)i));
        }
    }
}

/* ══════════════════════════════════════════════════════════════════
 *  Java — JSR 356 WebSocket, Spring STOMP/WebSocket
 * ══════════════════════════════════════════════════════════════════ */

static void java_process_call(CBMExtractCtx *ctx, TSNode call) {
    TSNode func = ts_node_child_by_field_name(call, TS_FIELD("name"));
    TSNode object = ts_node_child_by_field_name(call, TS_FIELD("object"));
    if (ts_node_is_null(func)) {
        return;
    }

    char *method = cbm_node_text(ctx->arena, func, ctx->source);
    if (!method) {
        return;
    }

    /* Spring STOMP: template.convertAndSend("/topic/...", msg) */
    if (strcmp(method, "convertAndSend") == 0 || strcmp(method, "convertAndSendToUser") == 0) {
        TSNode args = ts_node_child_by_field_name(call, TS_FIELD("arguments"));
        if (ts_node_is_null(args)) {
            return;
        }
        const char *channel_name = extract_channel_name(ctx, args, NULL);
        if (channel_name) {
            push_channel(ctx, channel_name, "spring_websocket", CBM_CHANNEL_EMIT, call);
        }
        return;
    }

    /* JSR 356: session.getBasicRemote().sendText(msg) — detect sendText/sendObject */
    if (strcmp(method, "sendText") == 0 || strcmp(method, "sendObject") == 0 ||
        strcmp(method, "sendBinary") == 0) {
        const char *func_name = enclosing_function_qn(ctx, call);
        const char *channel_name = func_name ? func_name : "(websocket)";
        push_channel(ctx, channel_name, "websocket", CBM_CHANNEL_EMIT, call);
        return;
    }

    (void)object;
}

/* Detect Java annotation-based WebSocket listeners: @OnMessage, @MessageMapping */
static void java_process_annotation(CBMExtractCtx *ctx, TSNode annotation) {
    TSNode name_node = ts_node_child_by_field_name(annotation, TS_FIELD("name"));
    if (ts_node_is_null(name_node)) {
        return;
    }
    char *name = cbm_node_text(ctx->arena, name_node, ctx->source);
    if (!name) {
        return;
    }

    if (strcmp(name, "OnMessage") == 0 || strcmp(name, "OnOpen") == 0 ||
        strcmp(name, "OnClose") == 0) {
        const char *func_name = enclosing_function_qn(ctx, annotation);
        const char *channel_name = func_name ? func_name : "(websocket)";
        push_channel(ctx, channel_name, "websocket", CBM_CHANNEL_LISTEN, annotation);
    } else if (strcmp(name, "MessageMapping") == 0) {
        /* @MessageMapping("/path") — extract the path */
        TSNode args = ts_node_child_by_field_name(annotation, TS_FIELD("arguments"));
        if (!ts_node_is_null(args)) {
            const char *path = extract_channel_name(ctx, args, NULL);
            if (path) {
                push_channel(ctx, path, "spring_websocket", CBM_CHANNEL_LISTEN, annotation);
                return;
            }
        }
        push_channel(ctx, "(spring_ws)", "spring_websocket", CBM_CHANNEL_LISTEN, annotation);
    } else if (strcmp(name, "ServerEndpoint") == 0) {
        TSNode args = ts_node_child_by_field_name(annotation, TS_FIELD("arguments"));
        if (!ts_node_is_null(args)) {
            const char *path = extract_channel_name(ctx, args, NULL);
            if (path) {
                push_channel(ctx, path, "websocket", CBM_CHANNEL_LISTEN, annotation);
                return;
            }
        }
    }
}

static void extract_channels_java(CBMExtractCtx *ctx) {
    TSNodeStack stack;
    ts_nstack_init(&stack, ctx->arena, CHAN_STACK_CAP);
    ts_nstack_push(&stack, ctx->arena, ctx->root);

    while (stack.count > 0) {
        TSNode node = ts_nstack_pop(&stack);
        const char *kind = ts_node_type(node);
        if (strcmp(kind, "method_invocation") == 0) {
            java_process_call(ctx, node);
        } else if (strcmp(kind, "marker_annotation") == 0 || strcmp(kind, "annotation") == 0) {
            java_process_annotation(ctx, node);
        }
        uint32_t count = ts_node_child_count(node);
        for (int i = (int)count - SKIP_ONE; i >= 0; i--) {
            ts_nstack_push(&stack, ctx->arena, ts_node_child(node, (uint32_t)i));
        }
    }
}

/* ══════════════════════════════════════════════════════════════════
 *  C# — SignalR (Clients.All.SendAsync / Hub.On)
 * ══════════════════════════════════════════════════════════════════ */

static void csharp_process_call(CBMExtractCtx *ctx, TSNode call) {
    TSNode func = ts_node_child_by_field_name(call, TS_FIELD("function"));
    if (ts_node_is_null(func)) {
        return;
    }
    const char *fk = ts_node_type(func);
    if (strcmp(fk, "member_access_expression") != 0) {
        return;
    }
    TSNode name_node = ts_node_child_by_field_name(func, TS_FIELD("name"));
    if (ts_node_is_null(name_node)) {
        return;
    }
    char *method = cbm_node_text(ctx->arena, name_node, ctx->source);
    if (!method) {
        return;
    }

    /* SignalR: Clients.All.SendAsync("method", data) */
    if (strcmp(method, "SendAsync") == 0 || strcmp(method, "SendCoreAsync") == 0) {
        char *full = cbm_node_text(ctx->arena, func, ctx->source);
        if (full && (strstr(full, "Clients") || strstr(full, "clients"))) {
            TSNode args = ts_node_child_by_field_name(call, TS_FIELD("arguments"));
            if (!ts_node_is_null(args)) {
                const char *channel_name = extract_channel_name(ctx, args, NULL);
                if (channel_name) {
                    push_channel(ctx, channel_name, "signalr", CBM_CHANNEL_EMIT, call);
                }
            }
        }
        return;
    }

    /* SignalR: connection.On<T>("method", handler) */
    if (strcmp(method, "On") == 0) {
        TSNode args = ts_node_child_by_field_name(call, TS_FIELD("arguments"));
        if (!ts_node_is_null(args)) {
            const char *channel_name = extract_channel_name(ctx, args, NULL);
            if (channel_name) {
                push_channel(ctx, channel_name, "signalr", CBM_CHANNEL_LISTEN, call);
            }
        }
    }
}

static void extract_channels_csharp(CBMExtractCtx *ctx) {
    TSNodeStack stack;
    ts_nstack_init(&stack, ctx->arena, CHAN_STACK_CAP);
    ts_nstack_push(&stack, ctx->arena, ctx->root);

    while (stack.count > 0) {
        TSNode node = ts_nstack_pop(&stack);
        if (strcmp(ts_node_type(node), "invocation_expression") == 0) {
            csharp_process_call(ctx, node);
        }
        uint32_t count = ts_node_child_count(node);
        for (int i = (int)count - SKIP_ONE; i >= 0; i--) {
            ts_nstack_push(&stack, ctx->arena, ts_node_child(node, (uint32_t)i));
        }
    }
}

/* ══════════════════════════════════════════════════════════════════
 *  Ruby — ActionCable (broadcast / stream_from)
 * ══════════════════════════════════════════════════════════════════ */

static void ruby_process_call(CBMExtractCtx *ctx, TSNode call) {
    const char *kind = ts_node_type(call);
    TSNode method_node;

    if (strcmp(kind, "call") == 0) {
        method_node = ts_node_child_by_field_name(call, TS_FIELD("method"));
    } else {
        return;
    }

    if (ts_node_is_null(method_node)) {
        return;
    }
    char *method = cbm_node_text(ctx->arena, method_node, ctx->source);
    if (!method) {
        return;
    }

    /* ActionCable.server.broadcast("channel", data) */
    if (strcmp(method, "broadcast") == 0) {
        TSNode args = ts_node_child_by_field_name(call, TS_FIELD("arguments"));
        if (!ts_node_is_null(args)) {
            const char *channel_name = extract_channel_name(ctx, args, NULL);
            if (channel_name) {
                push_channel(ctx, channel_name, "actioncable", CBM_CHANNEL_EMIT, call);
            }
        }
        return;
    }

    /* stream_from "channel" — listener registration */
    if (strcmp(method, "stream_from") == 0 || strcmp(method, "stream_for") == 0) {
        TSNode args = ts_node_child_by_field_name(call, TS_FIELD("arguments"));
        if (!ts_node_is_null(args)) {
            const char *channel_name = extract_channel_name(ctx, args, NULL);
            if (channel_name) {
                push_channel(ctx, channel_name, "actioncable", CBM_CHANNEL_LISTEN, call);
            }
        }
    }
}

static void extract_channels_ruby(CBMExtractCtx *ctx) {
    TSNodeStack stack;
    ts_nstack_init(&stack, ctx->arena, CHAN_STACK_CAP);
    ts_nstack_push(&stack, ctx->arena, ctx->root);

    while (stack.count > 0) {
        TSNode node = ts_nstack_pop(&stack);
        if (strcmp(ts_node_type(node), "call") == 0) {
            ruby_process_call(ctx, node);
        }
        uint32_t count = ts_node_child_count(node);
        for (int i = (int)count - SKIP_ONE; i >= 0; i--) {
            ts_nstack_push(&stack, ctx->arena, ts_node_child(node, (uint32_t)i));
        }
    }
}

/* ══════════════════════════════════════════════════════════════════
 *  Elixir — Phoenix.PubSub, Phoenix.Channel
 * ══════════════════════════════════════════════════════════════════ */

/* Extract a string literal from the Nth named child of an args node. */
static const char *elixir_nth_arg_literal(CBMExtractCtx *ctx, TSNode args, uint32_t index) {
    uint32_t ac = ts_node_named_child_count(args);
    if (ac <= index) {
        return NULL;
    }
    TSNode arg = ts_node_named_child(args, index);
    const char *val = literal_from_arg(ctx, arg);
    if (!val) {
        val = literal_from_first_child(ctx, arg);
    }
    return val;
}

/* Try to emit a channel from the second argument of an Elixir call. */
static void elixir_emit_second_arg(CBMExtractCtx *ctx, TSNode call, TSNode args,
                                   const char *transport, CBMChannelDirection direction) {
    if (ts_node_is_null(args)) {
        return;
    }
    const char *val = elixir_nth_arg_literal(ctx, args, SKIP_ONE);
    if (val) {
        push_channel(ctx, val, transport, direction, call);
    }
}

static void elixir_process_call(CBMExtractCtx *ctx, TSNode call) {
    TSNode target = ts_node_child_by_field_name(call, TS_FIELD("target"));
    if (ts_node_is_null(target)) {
        return;
    }
    char *target_text = cbm_node_text(ctx->arena, target, ctx->source);
    if (!target_text) {
        return;
    }

    TSNode args = ts_node_child_by_field_name(call, TS_FIELD("arguments"));

    if (strstr(target_text, "PubSub.broadcast") || strstr(target_text, "PubSub.local_broadcast")) {
        elixir_emit_second_arg(ctx, call, args, "phoenix_pubsub", CBM_CHANNEL_EMIT);
        return;
    }
    if (strstr(target_text, "PubSub.subscribe")) {
        elixir_emit_second_arg(ctx, call, args, "phoenix_pubsub", CBM_CHANNEL_LISTEN);
        return;
    }
    if (strcmp(target_text, "push") == 0 || strcmp(target_text, "broadcast") == 0 ||
        strcmp(target_text, "broadcast!") == 0) {
        elixir_emit_second_arg(ctx, call, args, "phoenix_channel", CBM_CHANNEL_EMIT);
    }
}

/* Detect handle_in("event", payload, socket) — Phoenix Channel listener */
static void elixir_process_function_def(CBMExtractCtx *ctx, TSNode func_def) {
    TSNode name_node = ts_node_child_by_field_name(func_def, TS_FIELD("name"));
    if (ts_node_is_null(name_node)) {
        return;
    }
    char *name = cbm_node_text(ctx->arena, name_node, ctx->source);
    if (!name || strcmp(name, "handle_in") != 0) {
        return;
    }
    /* First parameter is the event name pattern */
    TSNode params = ts_node_child_by_field_name(func_def, TS_FIELD("parameters"));
    if (ts_node_is_null(params)) {
        return;
    }
    uint32_t pc = ts_node_named_child_count(params);
    if (pc == 0) {
        return;
    }
    TSNode first_param = ts_node_named_child(params, 0);
    const char *val = literal_from_arg(ctx, first_param);
    if (!val) {
        val = literal_from_first_child(ctx, first_param);
    }
    if (val) {
        push_channel(ctx, val, "phoenix_channel", CBM_CHANNEL_LISTEN, func_def);
    }
}

static void extract_channels_elixir(CBMExtractCtx *ctx) {
    TSNodeStack stack;
    ts_nstack_init(&stack, ctx->arena, CHAN_STACK_CAP);
    ts_nstack_push(&stack, ctx->arena, ctx->root);

    while (stack.count > 0) {
        TSNode node = ts_nstack_pop(&stack);
        const char *kind = ts_node_type(node);
        if (strcmp(kind, "call") == 0) {
            elixir_process_call(ctx, node);
        } else if (strcmp(kind, "def") == 0) {
            elixir_process_function_def(ctx, node);
        }
        uint32_t count = ts_node_child_count(node);
        for (int i = (int)count - SKIP_ONE; i >= 0; i--) {
            ts_nstack_push(&stack, ctx->arena, ts_node_child(node, (uint32_t)i));
        }
    }
}

/* ══════════════════════════════════════════════════════════════════
 *  Rust — tokio-tungstenite (sink.send / stream.next)
 * ══════════════════════════════════════════════════════════════════ */

static void rust_process_call(CBMExtractCtx *ctx, TSNode call) {
    TSNode func = ts_node_child_by_field_name(call, TS_FIELD("function"));
    if (ts_node_is_null(func)) {
        return;
    }
    const char *fk = ts_node_type(func);
    if (strcmp(fk, "field_expression") != 0) {
        return;
    }
    TSNode field = ts_node_child_by_field_name(func, TS_FIELD("field"));
    TSNode value = ts_node_child_by_field_name(func, TS_FIELD("value"));
    if (ts_node_is_null(field) || ts_node_is_null(value)) {
        return;
    }

    char *method = cbm_node_text(ctx->arena, field, ctx->source);
    if (!method) {
        return;
    }

    CBMChannelDirection direction;
    if (strcmp(method, "send") == 0 || strcmp(method, "send_all") == 0 ||
        strcmp(method, "feed") == 0) {
        direction = CBM_CHANNEL_EMIT;
    } else if (strcmp(method, "next") == 0 || strcmp(method, "try_next") == 0) {
        direction = CBM_CHANNEL_LISTEN;
    } else {
        return;
    }

    /* Verify receiver looks like a websocket sink/stream */
    char *recv = cbm_node_text(ctx->arena, value, ctx->source);
    if (!recv) {
        return;
    }
    const char *tail = recv;
    const char *dot = strrchr(tail, '.');
    if (dot) {
        tail = dot + SKIP_ONE;
    }
    if (strcmp(tail, "sink") != 0 && strcmp(tail, "ws_sender") != 0 &&
        strcmp(tail, "writer") != 0 && strcmp(tail, "write") != 0 && strcmp(tail, "stream") != 0 &&
        strcmp(tail, "ws_receiver") != 0 && strcmp(tail, "reader") != 0 &&
        strcmp(tail, "read") != 0 && strcmp(tail, "ws_stream") != 0 && strcmp(tail, "ws") != 0) {
        return;
    }

    const char *func_name = enclosing_function_qn(ctx, call);
    const char *channel_name = func_name ? func_name : "(websocket)";
    push_channel(ctx, channel_name, "websocket", direction, call);
}

static void extract_channels_rust(CBMExtractCtx *ctx) {
    TSNodeStack stack;
    ts_nstack_init(&stack, ctx->arena, CHAN_STACK_CAP);
    ts_nstack_push(&stack, ctx->arena, ctx->root);

    while (stack.count > 0) {
        TSNode node = ts_nstack_pop(&stack);
        if (strcmp(ts_node_type(node), "call_expression") == 0) {
            rust_process_call(ctx, node);
        }
        uint32_t count = ts_node_child_count(node);
        for (int i = (int)count - SKIP_ONE; i >= 0; i--) {
            ts_nstack_push(&stack, ctx->arena, ts_node_child(node, (uint32_t)i));
        }
    }
}

/* ══════════════════════════════════════════════════════════════════
 *  Entry point — language dispatch
 * ══════════════════════════════════════════════════════════════════ */

void cbm_extract_channels(CBMExtractCtx *ctx) {
    switch (ctx->language) {
    case CBM_LANG_JAVASCRIPT:
    case CBM_LANG_TYPESCRIPT:
    case CBM_LANG_TSX:
        extract_channels_js(ctx);
        break;
    case CBM_LANG_PYTHON:
        extract_channels_python(ctx);
        break;
    case CBM_LANG_GO:
        extract_channels_go(ctx);
        break;
    case CBM_LANG_JAVA:
    case CBM_LANG_KOTLIN:
        extract_channels_java(ctx);
        break;
    case CBM_LANG_CSHARP:
        extract_channels_csharp(ctx);
        break;
    case CBM_LANG_RUBY:
        extract_channels_ruby(ctx);
        break;
    case CBM_LANG_ELIXIR:
        extract_channels_elixir(ctx);
        break;
    case CBM_LANG_RUST:
        extract_channels_rust(ctx);
        break;
    default:
        break; /* no channel detection for this language */
    }
}
