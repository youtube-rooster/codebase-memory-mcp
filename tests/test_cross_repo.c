/*
 * test_cross_repo.c — Input, work-bound, and write-failure guards for the
 * cross-repository matching pass.
 */
#include "test_framework.h"
#include "test_helpers.h"

#include "foundation/compat.h"
#include "pipeline/pass_cross_repo.h"
#include "pipeline/pipeline_internal.h"

#include <sqlite3/sqlite3.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if !defined(_WIN32)
#include <sys/wait.h>
#endif

typedef struct {
    char cache[256];
    char *saved_cache;
} cross_repo_fixture_t;

static bool cross_repo_fixture_begin(cross_repo_fixture_t *fixture) {
    memset(fixture, 0, sizeof(*fixture));
    const char *saved = getenv("CBM_CACHE_DIR");
    if (saved) {
        fixture->saved_cache = strdup(saved);
        if (!fixture->saved_cache) {
            return false;
        }
    }
    snprintf(fixture->cache, sizeof(fixture->cache), "/tmp/cbm-cross-hardening-XXXXXX");
    return cbm_mkdtemp(fixture->cache) != NULL &&
           cbm_setenv("CBM_CACHE_DIR", fixture->cache, 1) == 0;
}

static void cross_repo_fixture_end(cross_repo_fixture_t *fixture) {
    if (fixture->saved_cache) {
        (void)cbm_setenv("CBM_CACHE_DIR", fixture->saved_cache, 1);
    } else {
        (void)cbm_unsetenv("CBM_CACHE_DIR");
    }
    if (fixture->cache[0]) {
        th_rmtree(fixture->cache);
    }
    free(fixture->saved_cache);
    memset(fixture, 0, sizeof(*fixture));
}

static bool cross_repo_project_path(const cross_repo_fixture_t *fixture, const char *project,
                                    char *out, size_t out_size) {
    int written = snprintf(out, out_size, "%s/%s.db", fixture->cache, project);
    return written > 0 && (size_t)written < out_size;
}

static bool cross_repo_create_project(const cross_repo_fixture_t *fixture, const char *project) {
    char path[512];
    if (!cross_repo_project_path(fixture, project, path, sizeof(path))) {
        return false;
    }
    cbm_store_t *store = cbm_store_open_path(path);
    if (!store) {
        return false;
    }
    bool ok = cbm_store_upsert_project(store, project, fixture->cache) == CBM_STORE_OK;
    cbm_store_close(store);
    return ok;
}

/* Seed one HTTP_CALLS/HANDLES pair into two exact project stores. The suffix
 * keeps node QNs unique when a source is linked to more than one target. */
static bool cross_repo_seed_http_pair_files(const cross_repo_fixture_t *fixture,
                                            const char *source_project, const char *target_project,
                                            const char *route_path, const char *suffix,
                                            const char *caller_file, const char *handler_file) {
    char source_path[512];
    char target_path[512];
    if (!cross_repo_project_path(fixture, source_project, source_path, sizeof(source_path)) ||
        !cross_repo_project_path(fixture, target_project, target_path, sizeof(target_path))) {
        return false;
    }
    cbm_store_t *source = cbm_store_open_path(source_path);
    cbm_store_t *target = cbm_store_open_path(target_path);
    if (!source || !target) {
        cbm_store_close(source);
        cbm_store_close(target);
        return false;
    }

    bool ok = cbm_store_upsert_project(source, source_project, fixture->cache) == CBM_STORE_OK &&
              cbm_store_upsert_project(target, target_project, fixture->cache) == CBM_STORE_OK;
    char caller_qn[256];
    char local_route_qn[256];
    char target_route_qn[256];
    char handler_qn[256];
    char route_name[128];
    char edge_props[256];
    snprintf(caller_qn, sizeof(caller_qn), "%s.call.%s", source_project, suffix);
    snprintf(local_route_qn, sizeof(local_route_qn), "%s.local-route.%s", source_project, suffix);
    snprintf(target_route_qn, sizeof(target_route_qn), "__route__GET__%s", route_path);
    snprintf(handler_qn, sizeof(handler_qn), "%s.handle.%s", target_project, suffix);
    snprintf(route_name, sizeof(route_name), "GET %s", route_path);
    snprintf(edge_props, sizeof(edge_props), "{\"url_path\":\"%s\",\"method\":\"GET\"}",
             route_path);

    cbm_node_t caller = {.project = source_project,
                         .label = "Function",
                         .name = "call_remote",
                         .qualified_name = caller_qn,
                         .file_path = caller_file};
    cbm_node_t local_route = {.project = source_project,
                              .label = "Route",
                              .name = route_name,
                              .qualified_name = local_route_qn,
                              .file_path = caller_file};
    int64_t caller_id = ok ? cbm_store_upsert_node(source, &caller) : 0;
    int64_t local_route_id = ok ? cbm_store_upsert_node(source, &local_route) : 0;
    cbm_edge_t http_call = {.project = source_project,
                            .source_id = caller_id,
                            .target_id = local_route_id,
                            .type = "HTTP_CALLS",
                            .properties_json = edge_props};
    ok = ok && caller_id > 0 && local_route_id > 0 && cbm_store_insert_edge(source, &http_call) > 0;

    cbm_node_t target_route = {.project = target_project,
                               .label = "Route",
                               .name = route_name,
                               .qualified_name = target_route_qn,
                               .file_path = handler_file};
    cbm_node_t handler = {.project = target_project,
                          .label = "Function",
                          .name = "handle_remote",
                          .qualified_name = handler_qn,
                          .file_path = handler_file};
    int64_t target_route_id = ok ? cbm_store_upsert_node(target, &target_route) : 0;
    int64_t handler_id = ok ? cbm_store_upsert_node(target, &handler) : 0;
    cbm_edge_t handles = {.project = target_project,
                          .source_id = handler_id,
                          .target_id = target_route_id,
                          .type = "HANDLES"};
    ok = ok && target_route_id > 0 && handler_id > 0 && cbm_store_insert_edge(target, &handles) > 0;

    cbm_store_close(source);
    cbm_store_close(target);
    return ok;
}

static bool cross_repo_exec(const cross_repo_fixture_t *fixture, const char *project,
                            const char *sql) {
    char path[512];
    if (!cross_repo_project_path(fixture, project, path, sizeof(path))) {
        return false;
    }
    cbm_store_t *store = cbm_store_open_path_existing(path);
    if (!store) {
        return false;
    }
    char *error = NULL;
    int rc = sqlite3_exec(cbm_store_get_db(store), sql, NULL, NULL, &error);
    sqlite3_free(error);
    cbm_store_close(store);
    return rc == SQLITE_OK;
}

static int cross_repo_count_edges(const cross_repo_fixture_t *fixture, const char *project,
                                  const char *edge_type) {
    char path[512];
    if (!cross_repo_project_path(fixture, project, path, sizeof(path))) {
        return -1;
    }
    cbm_store_t *store = cbm_store_open_path_query(path);
    if (!store) {
        return -1;
    }
    int count = cbm_store_count_edges_by_type(store, project, edge_type);
    cbm_store_close(store);
    return count;
}

static bool cross_repo_seed_http_pair(const cross_repo_fixture_t *fixture,
                                      const char *source_project, const char *target_project,
                                      const char *route_path, const char *suffix) {
    return cross_repo_seed_http_pair_files(fixture, source_project, target_project, route_path,
                                           suffix, "client.c", "server.c");
}

TEST(cross_repo_null_target_fails_without_dereference) {
    cross_repo_fixture_t fixture;
    if (!cross_repo_fixture_begin(&fixture) ||
        !cross_repo_create_project(&fixture, "null-target-source")) {
        cross_repo_fixture_end(&fixture);
        FAIL("failed to create isolated source project");
    }

    bool rejected = false;
#if defined(_WIN32)
    const char *targets[] = {NULL};
    cbm_cross_repo_result_t result = cbm_cross_repo_match("null-target-source", targets, 1);
    rejected = result.failed;
#else
    fflush(NULL);
    pid_t child = fork();
    if (child == 0) {
        const char *targets[] = {NULL};
        cbm_cross_repo_result_t result = cbm_cross_repo_match("null-target-source", targets, 1);
        _exit(result.failed ? 0 : 2);
    }
    int status = 0;
    rejected = child > 0 && waitpid(child, &status, 0) == child && WIFEXITED(status) &&
               WEXITSTATUS(status) == 0;
#endif

    cross_repo_fixture_end(&fixture);
    ASSERT_TRUE(rejected);
    PASS();
}

TEST(cross_repo_wildcard_keeps_projects_containing_internal_tokens) {
    cross_repo_fixture_t fixture;
    bool setup = cross_repo_fixture_begin(&fixture) &&
                 cross_repo_seed_http_pair(&fixture, "wildcard-source", "orders_config_service",
                                           "/config-orders", "a") &&
                 cross_repo_seed_http_pair(&fixture, "wildcard-source", "orders_cross_repo_service",
                                           "/cross-orders", "b") &&
                 cross_repo_seed_http_pair(&fixture, "wildcard-source", "orders-wal-service",
                                           "/wal-orders", "c") &&
                 cross_repo_seed_http_pair(&fixture, "wildcard-source", "orders-shm-service",
                                           "/shm-orders", "d");
    if (!setup) {
        cross_repo_fixture_end(&fixture);
        FAIL("failed to seed wildcard fixture");
    }

    const char *targets[] = {"*"};
    cbm_cross_repo_result_t result = cbm_cross_repo_match("wildcard-source", targets, 1);
    cross_repo_fixture_end(&fixture);

    ASSERT_FALSE(result.failed);
    ASSERT_EQ(result.projects_scanned, 4);
    ASSERT_EQ(result.http_edges, 4);
    PASS();
}

static bool cross_repo_seed_bounded_scan(const cross_repo_fixture_t *fixture,
                                         const char *source_project, const char *target_project) {
    enum { TEST_SCAN_ROWS = 4097 };
    char source_path[512];
    char target_path[512];
    if (!cross_repo_project_path(fixture, source_project, source_path, sizeof(source_path)) ||
        !cross_repo_project_path(fixture, target_project, target_path, sizeof(target_path))) {
        return false;
    }
    cbm_store_t *source = cbm_store_open_path(source_path);
    cbm_store_t *target = cbm_store_open_path(target_path);
    if (!source || !target) {
        cbm_store_close(source);
        cbm_store_close(target);
        return false;
    }
    bool ok = cbm_store_upsert_project(source, source_project, fixture->cache) == CBM_STORE_OK &&
              cbm_store_upsert_project(target, target_project, fixture->cache) == CBM_STORE_OK;
    cbm_node_t caller = {.project = source_project,
                         .label = "Function",
                         .name = "bounded_caller",
                         .qualified_name = "bounded.source.caller",
                         .file_path = "client.c"};
    int64_t caller_id = ok ? cbm_store_upsert_node(source, &caller) : 0;
    ok = ok && caller_id > 0 &&
         sqlite3_exec(cbm_store_get_db(source), "BEGIN IMMEDIATE", NULL, NULL, NULL) == SQLITE_OK;
    for (int i = 0; ok && i < TEST_SCAN_ROWS; i++) {
        char name[64];
        char qn[96];
        snprintf(name, sizeof(name), "local_route_%d", i);
        snprintf(qn, sizeof(qn), "bounded.source.route.%d", i);
        cbm_node_t local_route = {.project = source_project,
                                  .label = "Route",
                                  .name = name,
                                  .qualified_name = qn,
                                  .file_path = "client.c"};
        int64_t route_id = cbm_store_upsert_node(source, &local_route);
        cbm_edge_t edge = {
            .project = source_project,
            .source_id = caller_id,
            .target_id = route_id,
            .type = "HTTP_CALLS",
            .properties_json = i == TEST_SCAN_ROWS - 1
                                   ? "{\"url_path\":\"/after-bound\",\"method\":\"GET\"}"
                                   : "{}",
        };
        ok = route_id > 0 && cbm_store_insert_edge(source, &edge) > 0;
    }
    if (ok) {
        ok = sqlite3_exec(cbm_store_get_db(source), "COMMIT", NULL, NULL, NULL) == SQLITE_OK;
    } else {
        (void)sqlite3_exec(cbm_store_get_db(source), "ROLLBACK", NULL, NULL, NULL);
    }

    cbm_node_t target_route = {.project = target_project,
                               .label = "Route",
                               .name = "GET /after-bound",
                               .qualified_name = "__route__GET__/after-bound",
                               .file_path = "server.c"};
    cbm_node_t handler = {.project = target_project,
                          .label = "Function",
                          .name = "bounded_handler",
                          .qualified_name = "bounded.target.handler",
                          .file_path = "server.c"};
    int64_t target_route_id = ok ? cbm_store_upsert_node(target, &target_route) : 0;
    int64_t handler_id = ok ? cbm_store_upsert_node(target, &handler) : 0;
    cbm_edge_t handles = {.project = target_project,
                          .source_id = handler_id,
                          .target_id = target_route_id,
                          .type = "HANDLES"};
    ok = ok && target_route_id > 0 && handler_id > 0 && cbm_store_insert_edge(target, &handles) > 0;
    cbm_store_close(source);
    cbm_store_close(target);
    return ok;
}

TEST(cross_repo_scan_bound_counts_examined_rows_not_matches) {
    cross_repo_fixture_t fixture;
    bool setup = cross_repo_fixture_begin(&fixture) &&
                 cross_repo_seed_bounded_scan(&fixture, "bounded-source", "bounded-target");
    if (!setup) {
        cross_repo_fixture_end(&fixture);
        FAIL("failed to seed bounded scan fixture");
    }
    const char *target = "bounded-target";
    cbm_cross_repo_result_t result = cbm_cross_repo_match("bounded-source", &target, 1);
    cross_repo_fixture_end(&fixture);

    ASSERT_FALSE(result.failed);
    ASSERT_EQ(result.projects_scanned, 1);
    ASSERT_EQ(result.http_edges, 0);
    PASS();
}

TEST(cross_repo_propagates_delete_failure) {
    cross_repo_fixture_t fixture;
    bool setup = cross_repo_fixture_begin(&fixture) &&
                 cross_repo_seed_http_pair(&fixture, "delete-source", "delete-target",
                                           "/delete-failure", "delete");
    if (!setup) {
        cross_repo_fixture_end(&fixture);
        FAIL("failed to seed delete failure fixture");
    }
    const char *target = "delete-target";
    cbm_cross_repo_result_t initial = cbm_cross_repo_match("delete-source", &target, 1);
    bool trigger_created =
        !initial.failed && initial.http_edges == 1 &&
        cross_repo_exec(&fixture, "delete-source",
                        "CREATE TRIGGER fail_cross_delete BEFORE DELETE ON edges "
                        "WHEN OLD.type = 'CROSS_HTTP_CALLS' BEGIN "
                        "SELECT RAISE(ABORT, 'forced cross delete failure'); END;");
    cbm_cross_repo_result_t failed = {0};
    if (trigger_created) {
        failed = cbm_cross_repo_match("delete-source", &target, 1);
    }
    cross_repo_fixture_end(&fixture);

    ASSERT_TRUE(trigger_created);
    ASSERT_TRUE(failed.failed);
    ASSERT_EQ(failed.http_edges, 0);
    PASS();
}

TEST(cross_repo_failed_bidirectional_insert_is_not_counted) {
    cross_repo_fixture_t fixture;
    bool setup = cross_repo_fixture_begin(&fixture) &&
                 cross_repo_seed_http_pair(&fixture, "insert-source", "insert-target",
                                           "/insert-failure", "insert") &&
                 cross_repo_exec(&fixture, "insert-target",
                                 "CREATE TRIGGER fail_cross_insert BEFORE INSERT ON edges "
                                 "WHEN NEW.type = 'CROSS_HTTP_CALLS' BEGIN "
                                 "SELECT RAISE(ABORT, 'forced cross insert failure'); END;");
    if (!setup) {
        cross_repo_fixture_end(&fixture);
        FAIL("failed to seed insert failure fixture");
    }
    const char *target = "insert-target";
    cbm_cross_repo_result_t result = cbm_cross_repo_match("insert-source", &target, 1);
    cross_repo_fixture_end(&fixture);

    ASSERT_TRUE(result.failed);
    ASSERT_EQ(result.http_edges, 0);
    ASSERT_EQ(result.projects_scanned, 0);
    PASS();
}

typedef struct {
    atomic_int *cancelled;
    int fired;
} cross_repo_cancel_hook_t;

static void cross_repo_cancel_after_target_write(const char *project, const char *edge_type,
                                                 void *opaque) {
    cross_repo_cancel_hook_t *hook = opaque;
    if (strcmp(project, "cancel-target-b") == 0 && strcmp(edge_type, "CROSS_HTTP_CALLS") == 0) {
        hook->fired++;
        atomic_store_explicit(hook->cancelled, 1, memory_order_release);
    }
}

TEST(cross_repo_cancel_mid_run_keeps_completed_target_and_stops_before_later_target) {
    cross_repo_fixture_t fixture;
    bool setup =
        cross_repo_fixture_begin(&fixture) &&
        cross_repo_seed_http_pair(&fixture, "cancel-source", "cancel-target-a", "/cancel-a", "a") &&
        cross_repo_seed_http_pair(&fixture, "cancel-source", "cancel-target-b", "/cancel-b", "b") &&
        cross_repo_seed_http_pair(&fixture, "cancel-source", "cancel-target-c", "/cancel-c", "c");
    if (!setup) {
        cross_repo_fixture_end(&fixture);
        FAIL("failed to seed cancellation fixture");
    }

    atomic_int cancelled;
    atomic_init(&cancelled, 0);
    cross_repo_cancel_hook_t hook = {
        .cancelled = &cancelled,
    };

    const char *targets[] = {"cancel-target-c", "cancel-target-a", "cancel-target-b"};
    cbm_cross_repo_set_after_insert_hook_for_tests(cross_repo_cancel_after_target_write, &hook);
    cbm_cross_repo_result_t result =
        cbm_cross_repo_match_cancellable("cancel-source", targets, 3, &cancelled);
    cbm_cross_repo_set_after_insert_hook_for_tests(NULL, NULL);

    int completed_target_edges =
        cross_repo_count_edges(&fixture, "cancel-target-a", "CROSS_HTTP_CALLS");
    int interrupted_target_edges =
        cross_repo_count_edges(&fixture, "cancel-target-b", "CROSS_HTTP_CALLS");
    int later_target_edges =
        cross_repo_count_edges(&fixture, "cancel-target-c", "CROSS_HTTP_CALLS");
    cross_repo_fixture_end(&fixture);

    ASSERT_EQ(hook.fired, 1);
    ASSERT_TRUE(result.cancelled);
    ASSERT_TRUE(result.partial_results);
    ASSERT_FALSE(result.failed);
    ASSERT_EQ(result.projects_scanned, 1);
    ASSERT_TRUE(completed_target_edges > 0);
    ASSERT_TRUE(interrupted_target_edges > 0);
    ASSERT_EQ(later_target_edges, 0);
    PASS();
}

TEST(cross_repo_pre_cancel_preserves_existing_cross_edges) {
    cross_repo_fixture_t fixture;
    bool setup = cross_repo_fixture_begin(&fixture) &&
                 cross_repo_seed_http_pair(&fixture, "pre-cancel-source", "pre-cancel-target",
                                           "/pre-cancel", "pre");
    if (!setup) {
        cross_repo_fixture_end(&fixture);
        FAIL("failed to seed pre-cancel fixture");
    }

    const char *target = "pre-cancel-target";
    cbm_cross_repo_result_t initial = cbm_cross_repo_match("pre-cancel-source", &target, 1);
    int before = cross_repo_count_edges(&fixture, "pre-cancel-source", "CROSS_HTTP_CALLS");
    atomic_int cancelled;
    atomic_init(&cancelled, 1);
    cbm_cross_repo_result_t result =
        cbm_cross_repo_match_cancellable("pre-cancel-source", &target, 1, &cancelled);
    int after = cross_repo_count_edges(&fixture, "pre-cancel-source", "CROSS_HTTP_CALLS");
    cross_repo_fixture_end(&fixture);

    ASSERT_FALSE(initial.failed);
    ASSERT_TRUE(before > 0);
    ASSERT_TRUE(result.cancelled);
    ASSERT_FALSE(result.partial_results);
    ASSERT_FALSE(result.failed);
    ASSERT_EQ(result.projects_scanned, 0);
    ASSERT_EQ(after, before);
    PASS();
}

/* Add the internal "<name>::missed" miss-graph row that indexing writes into
 * the SAME db whenever a file parses partially. */
static bool cross_repo_add_missed_shadow(const cross_repo_fixture_t *fixture, const char *project) {
    char path[512];
    char shadow[256];
    if (!cross_repo_project_path(fixture, project, path, sizeof(path))) {
        return false;
    }
    snprintf(shadow, sizeof(shadow), "%s::missed", project);
    cbm_store_t *store = cbm_store_open_path(path);
    if (!store) {
        return false;
    }
    bool ok = cbm_store_upsert_project(store, shadow, fixture->cache) == CBM_STORE_OK;
    cbm_store_close(store);
    return ok;
}

/* #1609: any project that has ever recorded a parse miss carries a
 * "<name>::missed" shadow row in its own db. cr_store_has_exact_project
 * demanded count == 1 over ALL rows, so that second row made the project
 * unresolvable — as source AND as target — and the whole feature failed with
 * "not indexed" for a project that plainly was. mcp.c already solved exactly
 * this shape for list_projects in #1044; this site never learned it.
 *
 * The control is the pair without shadow rows: the tests above already prove
 * that path returns edges, so a regression here cannot hide behind a fixture
 * that never matched in the first place. */
TEST(cross_repo_accepts_project_with_missed_shadow_row_issue1609) {
    cross_repo_fixture_t fixture;
    bool setup =
        cross_repo_fixture_begin(&fixture) &&
        cross_repo_seed_http_pair(&fixture, "shadow-source", "shadow-target", "/orders", "s") &&
        cross_repo_add_missed_shadow(&fixture, "shadow-source") &&
        cross_repo_add_missed_shadow(&fixture, "shadow-target");
    if (!setup) {
        cross_repo_fixture_end(&fixture);
        FAIL("failed to seed shadow-row fixture");
    }

    const char *target = "shadow-target";
    cbm_cross_repo_result_t result = cbm_cross_repo_match("shadow-source", &target, 1);
    cross_repo_fixture_end(&fixture);

    ASSERT_FALSE(result.failed);
    ASSERT_EQ(result.projects_scanned, 1);
    ASSERT_EQ(result.http_edges, 1);
    PASS();
}

/* ── Channel transport invariants ────────────────────────────────
 *
 * A Channel's identity is (name, transport): `message` on Socket.IO and
 * `message` on RabbitMQ are unrelated conversations that happen to share a
 * word.  The matcher must pair an emitter only with a listener on the SAME
 * transport — otherwise every generic event name (`message`, `error`,
 * `update`) fabricates cross-repo edges between services that never talk. */

static bool cross_repo_seed_channel_side(const cross_repo_fixture_t *fixture, const char *project,
                                         const char *channel_name, const char *transport,
                                         const char *edge_type, const char *fn_file) {
    char path[512];
    if (!cross_repo_project_path(fixture, project, path, sizeof(path))) {
        return false;
    }
    cbm_store_t *store = cbm_store_open_path(path);
    if (!store) {
        return false;
    }
    bool ok = cbm_store_upsert_project(store, project, fixture->cache) == CBM_STORE_OK;

    char fn_qn[256];
    char channel_qn[256];
    char channel_props[256];
    char edge_props[128];
    snprintf(fn_qn, sizeof(fn_qn), "%s.%s.%s", project, edge_type, channel_name);
    snprintf(channel_qn, sizeof(channel_qn), "__channel__%s__%s", transport, channel_name);
    snprintf(channel_props, sizeof(channel_props), "{\"transport\":\"%s\",\"name\":\"%s\"}",
             transport, channel_name);
    snprintf(edge_props, sizeof(edge_props), "{\"transport\":\"%s\"}", transport);

    cbm_node_t fn = {.project = project,
                     .label = "Function",
                     .name = "participant",
                     .qualified_name = fn_qn,
                     .file_path = fn_file};
    cbm_node_t channel = {.project = project,
                          .label = "Channel",
                          .name = channel_name,
                          .qualified_name = channel_qn,
                          .properties_json = channel_props};
    int64_t fn_id = ok ? cbm_store_upsert_node(store, &fn) : 0;
    int64_t channel_id = ok ? cbm_store_upsert_node(store, &channel) : 0;
    cbm_edge_t edge = {.project = project,
                       .source_id = fn_id,
                       .target_id = channel_id,
                       .type = edge_type,
                       .properties_json = edge_props};
    ok = ok && fn_id > 0 && channel_id > 0 && cbm_store_insert_edge(store, &edge) > 0;
    cbm_store_close(store);
    return ok;
}

TEST(cross_channel_same_name_and_transport_links) {
    cross_repo_fixture_t fixture;
    bool setup = cross_repo_fixture_begin(&fixture) &&
                 cross_repo_seed_channel_side(&fixture, "chan-source", "new_comment",
                                              "message_type", "EMITS", "publish.py") &&
                 cross_repo_seed_channel_side(&fixture, "chan-target", "new_comment",
                                              "message_type", "LISTENS_ON", "consumer.ts");
    if (!setup) {
        cross_repo_fixture_end(&fixture);
        FAIL("failed to seed matching channel fixture");
    }

    const char *target = "chan-target";
    cbm_cross_repo_result_t result = cbm_cross_repo_match("chan-source", &target, 1);
    int src_edges = cross_repo_count_edges(&fixture, "chan-source", "CROSS_CHANNEL");
    int tgt_edges = cross_repo_count_edges(&fixture, "chan-target", "CROSS_CHANNEL");
    cross_repo_fixture_end(&fixture);

    ASSERT_FALSE(result.failed);
    ASSERT_EQ(result.channel_edges, 1);
    ASSERT_EQ(src_edges, 1); /* forward: emitter → local Channel */
    ASSERT_EQ(tgt_edges, 1); /* reverse: listener → target Channel */
    PASS();
}

TEST(cross_channel_listener_side_run_keeps_its_edges) {
    /* A pass wipes the CROSS_* edges of the project it runs from and rebuilds
     * only what it matches from that project's EMITS.  A consumer-only
     * service therefore ended each of its own passes with zero channel edges:
     * the reverse edges a producer's pass had written into it were deleted
     * and nothing recreated them.  Measured: rcr-ws-server went 8 -> 2. */
    cross_repo_fixture_t fixture;
    bool setup = cross_repo_fixture_begin(&fixture) &&
                 cross_repo_seed_channel_side(&fixture, "producer", "dynamic_on_air",
                                              "message_type", "EMITS", "publisher.js") &&
                 cross_repo_seed_channel_side(&fixture, "consumer", "dynamic_on_air",
                                              "message_type", "LISTENS_ON", "mounter.ts");
    if (!setup) {
        cross_repo_fixture_end(&fixture);
        FAIL("failed to seed producer/consumer fixture");
    }

    const char *consumer = "consumer";
    cbm_cross_repo_result_t first = cbm_cross_repo_match("producer", &consumer, 1);
    int consumer_after_producer_run = cross_repo_count_edges(&fixture, "consumer", "CROSS_CHANNEL");

    const char *producer = "producer";
    cbm_cross_repo_result_t second = cbm_cross_repo_match("consumer", &producer, 1);
    int consumer_after_own_run = cross_repo_count_edges(&fixture, "consumer", "CROSS_CHANNEL");
    int producer_after_consumer_run = cross_repo_count_edges(&fixture, "producer", "CROSS_CHANNEL");
    cross_repo_fixture_end(&fixture);

    ASSERT_FALSE(first.failed);
    ASSERT_FALSE(second.failed);
    ASSERT_EQ(consumer_after_producer_run, 1);
    ASSERT_EQ(second.channel_edges, 1);
    ASSERT_EQ(consumer_after_own_run, 1);
    ASSERT_EQ(producer_after_consumer_run, 1);
    PASS();
}

TEST(cross_channel_ignores_transport_lifecycle_events) {
    /* Every raw WebSocket client listens on `message`, `close` and `error`,
     * and every Socket.IO server can emit them; pairing those names links a
     * service to every socket client in the workspace.  Measured: the only
     * edge between rcr-ws-server and rooster-public-api was `message`. */
    cross_repo_fixture_t fixture;
    bool setup = cross_repo_fixture_begin(&fixture) &&
                 cross_repo_seed_channel_side(&fixture, "life-source", "message", "socketio",
                                              "EMITS", "gateway.ts") &&
                 cross_repo_seed_channel_side(&fixture, "life-source", "close", "socketio", "EMITS",
                                              "gateway.ts") &&
                 cross_repo_seed_channel_side(&fixture, "life-target", "message", "socketio",
                                              "LISTENS_ON", "client.ts") &&
                 cross_repo_seed_channel_side(&fixture, "life-target", "close", "socketio",
                                              "LISTENS_ON", "client.ts");
    if (!setup) {
        cross_repo_fixture_end(&fixture);
        FAIL("failed to seed lifecycle channel fixture");
    }

    const char *target = "life-target";
    cbm_cross_repo_result_t result = cbm_cross_repo_match("life-source", &target, 1);
    int src_edges = cross_repo_count_edges(&fixture, "life-source", "CROSS_CHANNEL");
    int tgt_edges = cross_repo_count_edges(&fixture, "life-target", "CROSS_CHANNEL");
    cross_repo_fixture_end(&fixture);

    ASSERT_FALSE(result.failed);
    ASSERT_EQ(result.channel_edges, 0);
    ASSERT_EQ(src_edges, 0);
    ASSERT_EQ(tgt_edges, 0);
    PASS();
}

TEST(cross_channel_same_name_different_transport_does_not_link) {
    /* The negative invariant: a Socket.IO `message` emitter and a RabbitMQ
     * `message` consumer share nothing but a word.  Zero edges, both sides. */
    cross_repo_fixture_t fixture;
    bool setup = cross_repo_fixture_begin(&fixture) &&
                 cross_repo_seed_channel_side(&fixture, "mismatch-source", "message", "socketio",
                                              "EMITS", "socket.ts") &&
                 cross_repo_seed_channel_side(&fixture, "mismatch-target", "message", "rabbitmq",
                                              "LISTENS_ON", "consumer.ts");
    if (!setup) {
        cross_repo_fixture_end(&fixture);
        FAIL("failed to seed mismatched channel fixture");
    }

    const char *target = "mismatch-target";
    cbm_cross_repo_result_t result = cbm_cross_repo_match("mismatch-source", &target, 1);
    int src_edges = cross_repo_count_edges(&fixture, "mismatch-source", "CROSS_CHANNEL");
    int tgt_edges = cross_repo_count_edges(&fixture, "mismatch-target", "CROSS_CHANNEL");
    cross_repo_fixture_end(&fixture);

    ASSERT_FALSE(result.failed);
    ASSERT_EQ(result.channel_edges, 0);
    ASSERT_EQ(src_edges, 0);
    ASSERT_EQ(tgt_edges, 0);
    PASS();
}

/* A test fixture is not a caller. A suite seeds sample routes ("/admin/users")
 * and temp paths ("/tmp/test") as string literals to exercise the extractors;
 * the matcher read those literals as real traffic and wired them to whatever
 * project happened to serve a route of the same name. Measured on a 23-repo
 * workspace: 141 of the 145 cross edges leaving cbm's own project came from
 * tests/, 135 of them from the single literal "/tmp/test". */
TEST(cross_repo_ignores_http_call_declared_in_a_test_file) {
    cross_repo_fixture_t fixture;
    bool setup =
        cross_repo_fixture_begin(&fixture) &&
        cross_repo_seed_http_pair_files(&fixture, "testfile-source", "testfile-target",
                                        "/admin/users", "s", "tests/test_pipeline.c", "server.c");
    if (!setup) {
        cross_repo_fixture_end(&fixture);
        FAIL("failed to seed test-file caller fixture");
    }

    const char *target = "testfile-target";
    cbm_cross_repo_result_t result = cbm_cross_repo_match("testfile-source", &target, 1);
    int emitted = cross_repo_count_edges(&fixture, "testfile-source", "CROSS_HTTP_CALLS");
    cross_repo_fixture_end(&fixture);

    ASSERT_FALSE(result.failed);
    ASSERT_EQ(result.http_edges, 0);
    ASSERT_EQ(emitted, 0);
    PASS();
}

/* The mirror case: a Route that only exists inside the target's own suite is
 * not a service endpoint, so no real client can be calling it. */
TEST(cross_repo_ignores_route_declared_in_a_test_file) {
    cross_repo_fixture_t fixture;
    bool setup =
        cross_repo_fixture_begin(&fixture) &&
        cross_repo_seed_http_pair_files(&fixture, "testroute-source", "testroute-target",
                                        "/admin/users", "s", "client.c", "tests/test_server.c");
    if (!setup) {
        cross_repo_fixture_end(&fixture);
        FAIL("failed to seed test-file route fixture");
    }

    const char *target = "testroute-target";
    cbm_cross_repo_result_t result = cbm_cross_repo_match("testroute-source", &target, 1);
    int emitted = cross_repo_count_edges(&fixture, "testroute-source", "CROSS_HTTP_CALLS");
    cross_repo_fixture_end(&fixture);

    ASSERT_FALSE(result.failed);
    ASSERT_EQ(result.http_edges, 0);
    ASSERT_EQ(emitted, 0);
    PASS();
}

/* The same fixture problem on the broker side: a suite that publishes to a
 * queue name to exercise its own adapter is not a producer of that queue. */
TEST(cross_channel_ignores_emitter_in_a_test_file) {
    cross_repo_fixture_t fixture;
    bool setup = cross_repo_fixture_begin(&fixture) &&
                 cross_repo_seed_channel_side(&fixture, "chan-test-source", "new_comment",
                                              "message_type", "EMITS", "tests/test_worker.py") &&
                 cross_repo_seed_channel_side(&fixture, "chan-test-target", "new_comment",
                                              "message_type", "LISTENS_ON", "consumer.ts");
    if (!setup) {
        cross_repo_fixture_end(&fixture);
        FAIL("failed to seed test-file emitter fixture");
    }

    const char *target = "chan-test-target";
    cbm_cross_repo_result_t result = cbm_cross_repo_match("chan-test-source", &target, 1);
    int src_edges = cross_repo_count_edges(&fixture, "chan-test-source", "CROSS_CHANNEL");
    int tgt_edges = cross_repo_count_edges(&fixture, "chan-test-target", "CROSS_CHANNEL");
    cross_repo_fixture_end(&fixture);

    ASSERT_FALSE(result.failed);
    ASSERT_EQ(result.channel_edges, 0);
    ASSERT_EQ(src_edges, 0);
    ASSERT_EQ(tgt_edges, 0);
    PASS();
}

/* The mirror case on the broker side. cross_channel_same_name_and_transport_links
 * is the control: the identical fixture outside tests/ still links, so a filter
 * that dropped everything cannot pass green. */
TEST(cross_channel_ignores_listener_in_a_test_file) {
    cross_repo_fixture_t fixture;
    bool setup =
        cross_repo_fixture_begin(&fixture) &&
        cross_repo_seed_channel_side(&fixture, "chan-tlist-source", "new_comment", "message_type",
                                     "EMITS", "publish.py") &&
        cross_repo_seed_channel_side(&fixture, "chan-tlist-target", "new_comment", "message_type",
                                     "LISTENS_ON", "src/__tests__/consumer.test.ts");
    if (!setup) {
        cross_repo_fixture_end(&fixture);
        FAIL("failed to seed test-file listener fixture");
    }

    const char *target = "chan-tlist-target";
    cbm_cross_repo_result_t result = cbm_cross_repo_match("chan-tlist-source", &target, 1);
    cross_repo_fixture_end(&fixture);

    ASSERT_FALSE(result.failed);
    ASSERT_EQ(result.channel_edges, 0);
    PASS();
}

/* ── RabbitMQ bindings: exchange + routing key → queue ──────────── */

/* Like cross_repo_seed_channel_side, with the EMITS/LISTENS_ON edge carrying
 * the properties the pipeline would have written (`routing_keys`). */
static bool cross_repo_seed_keyed_channel(const cross_repo_fixture_t *fixture, const char *project,
                                          const char *channel_name, const char *edge_type,
                                          const char *edge_props, const char *fn_name,
                                          const char *fn_file) {
    char path[512];
    if (!cross_repo_project_path(fixture, project, path, sizeof(path))) {
        return false;
    }
    cbm_store_t *store = cbm_store_open_path(path);
    if (!store) {
        return false;
    }
    bool ok = cbm_store_upsert_project(store, project, fixture->cache) == CBM_STORE_OK;
    char fn_qn[256];
    char channel_qn[256];
    char channel_props[256];
    snprintf(fn_qn, sizeof(fn_qn), "%s.%s.%s", project, fn_file, fn_name);
    snprintf(channel_qn, sizeof(channel_qn), "__channel__rabbitmq__%s", channel_name);
    snprintf(channel_props, sizeof(channel_props), "{\"transport\":\"rabbitmq\",\"name\":\"%s\"}",
             channel_name);
    cbm_node_t fn = {.project = project,
                     .label = "Function",
                     .name = fn_name,
                     .qualified_name = fn_qn,
                     .file_path = fn_file};
    cbm_node_t channel = {.project = project,
                          .label = "Channel",
                          .name = channel_name,
                          .qualified_name = channel_qn,
                          .properties_json = channel_props};
    int64_t fn_id = ok ? cbm_store_upsert_node(store, &fn) : 0;
    int64_t channel_id = ok ? cbm_store_upsert_node(store, &channel) : 0;
    cbm_edge_t edge = {.project = project,
                       .source_id = fn_id,
                       .target_id = channel_id,
                       .type = edge_type,
                       .properties_json = edge_props};
    ok = ok && fn_id > 0 && channel_id > 0 && cbm_store_insert_edge(store, &edge) > 0;
    cbm_store_close(store);
    return ok;
}

/* One BINDS edge exchange → destination in the infra project's store, the
 * shape the definitions.json extractor materializes. */
static bool cross_repo_seed_binding(const cross_repo_fixture_t *fixture, const char *project,
                                    const char *exchange, const char *destination,
                                    const char *routing_keys_json) {
    char path[512];
    if (!cross_repo_project_path(fixture, project, path, sizeof(path))) {
        return false;
    }
    cbm_store_t *store = cbm_store_open_path(path);
    if (!store) {
        return false;
    }
    bool ok = cbm_store_upsert_project(store, project, fixture->cache) == CBM_STORE_OK;
    char ex_qn[256];
    char ex_props[256];
    char dest_qn[256];
    char dest_props[256];
    char edge_props[1024];
    snprintf(ex_qn, sizeof(ex_qn), "__channel__rabbitmq__%s", exchange);
    snprintf(ex_props, sizeof(ex_props), "{\"transport\":\"rabbitmq\",\"name\":\"%s\"}", exchange);
    snprintf(dest_qn, sizeof(dest_qn), "__channel__rabbitmq__%s", destination);
    snprintf(dest_props, sizeof(dest_props), "{\"transport\":\"rabbitmq\",\"name\":\"%s\"}",
             destination);
    snprintf(edge_props, sizeof(edge_props), "{\"transport\":\"rabbitmq\",\"routing_keys\":%s}",
             routing_keys_json);
    cbm_node_t ex = {.project = project,
                     .label = "Channel",
                     .name = exchange,
                     .qualified_name = ex_qn,
                     .properties_json = ex_props};
    cbm_node_t dest = {.project = project,
                       .label = "Channel",
                       .name = destination,
                       .qualified_name = dest_qn,
                       .properties_json = dest_props};
    int64_t ex_id = ok ? cbm_store_upsert_node(store, &ex) : 0;
    int64_t dest_id = ok ? cbm_store_upsert_node(store, &dest) : 0;
    cbm_edge_t edge = {.project = project,
                       .source_id = ex_id,
                       .target_id = dest_id,
                       .type = "BINDS",
                       .properties_json = edge_props};
    ok = ok && ex_id > 0 && dest_id > 0 && cbm_store_insert_edge(store, &edge) > 0;
    cbm_store_close(store);
    return ok;
}

/* True when some edge of `edge_type` in `project` has `needle` in its properties. */
static bool cross_repo_edge_props_have(const cross_repo_fixture_t *fixture, const char *project,
                                       const char *edge_type, const char *needle) {
    char path[512];
    if (!cross_repo_project_path(fixture, project, path, sizeof(path))) {
        return false;
    }
    cbm_store_t *store = cbm_store_open_path_query(path);
    if (!store) {
        return false;
    }
    sqlite3_stmt *q = NULL;
    bool found = false;
    if (sqlite3_prepare_v2(cbm_store_get_db(store),
                           "SELECT properties FROM edges WHERE project = ?1 AND type = ?2", -1, &q,
                           NULL) == SQLITE_OK) {
        sqlite3_bind_text(q, 1, project, -1, SQLITE_STATIC);
        sqlite3_bind_text(q, 2, edge_type, -1, SQLITE_STATIC);
        while (sqlite3_step(q) == SQLITE_ROW) {
            const char *props = (const char *)sqlite3_column_text(q, 0);
            if (props && strstr(props, needle)) {
                found = true;
                break;
            }
        }
        sqlite3_finalize(q);
    }
    cbm_store_close(store);
    return found;
}

TEST(cross_channel_resolves_exchange_and_key_through_binding_in_a_third_project) {
    cross_repo_fixture_t fixture;
    bool setup = cross_repo_fixture_begin(&fixture) &&
                 cross_repo_seed_keyed_channel(&fixture, "rb-producer",
                                               "comments.processed.exchange", "EMITS",
                                               "{\"transport\":\"rabbitmq\","
                                               "\"routing_keys\":[\"comments.processed\"]}",
                                               "publish_processed", "worker.py") &&
                 cross_repo_seed_binding(&fixture, "rb-infra", "comments.processed.exchange",
                                         "comments.processed.queue", "[\"comments.processed\"]") &&
                 cross_repo_seed_keyed_channel(&fixture, "rb-consumer", "comments.processed.queue",
                                               "LISTENS_ON", "{\"transport\":\"rabbitmq\"}",
                                               "consume_processed", "consumer.js");
    if (!setup) {
        cross_repo_fixture_end(&fixture);
        FAIL("failed to seed the binding fixture");
    }

    /* The infra project is not a target: the binding is found anyway. */
    const char *target = "rb-consumer";
    cbm_cross_repo_result_t result = cbm_cross_repo_match("rb-producer", &target, 1);
    int producer_edges = cross_repo_count_edges(&fixture, "rb-producer", "CROSS_CHANNEL");
    int consumer_edges = cross_repo_count_edges(&fixture, "rb-consumer", "CROSS_CHANNEL");
    int infra_edges = cross_repo_count_edges(&fixture, "rb-infra", "CROSS_CHANNEL");
    bool via = cross_repo_edge_props_have(&fixture, "rb-producer", "CROSS_CHANNEL",
                                          "\"via_exchange\":\"comments.processed.exchange\"");
    bool key = cross_repo_edge_props_have(&fixture, "rb-producer", "CROSS_CHANNEL",
                                          "\"routing_key\":\"comments.processed\"");
    bool who = cross_repo_edge_props_have(&fixture, "rb-producer", "CROSS_CHANNEL",
                                          "\"binding_project\":\"rb-infra\"");
    bool target_fn = cross_repo_edge_props_have(&fixture, "rb-producer", "CROSS_CHANNEL",
                                                "\"target_function\":\"consume_processed\"");
    bool queue_named = cross_repo_edge_props_have(&fixture, "rb-producer", "CROSS_CHANNEL",
                                                  "\"channel_name\":\"comments.processed.queue\"");
    bool reverse_props =
        cross_repo_edge_props_have(&fixture, "rb-consumer", "CROSS_CHANNEL",
                                   "\"via_exchange\":\"comments.processed.exchange\"");
    cross_repo_fixture_end(&fixture);

    ASSERT_FALSE(result.failed);
    ASSERT_EQ(result.channel_edges, 1);
    ASSERT_EQ(producer_edges, 1);
    ASSERT_EQ(consumer_edges, 1);
    ASSERT_EQ(infra_edges, 0);
    ASSERT_TRUE(via);
    ASSERT_TRUE(key);
    ASSERT_TRUE(who);
    ASSERT_TRUE(target_fn);
    ASSERT_TRUE(queue_named);
    ASSERT_TRUE(reverse_props);
    PASS();
}

TEST(cross_channel_consumer_side_run_resolves_the_binding_too) {
    cross_repo_fixture_t fixture;
    bool setup =
        cross_repo_fixture_begin(&fixture) &&
        cross_repo_seed_keyed_channel(&fixture, "rb-producer", "live.control.exchange", "EMITS",
                                      "{\"transport\":\"rabbitmq\","
                                      "\"routing_keys\":[\"live.control.start\"]}",
                                      "start_live", "control.js") &&
        cross_repo_seed_binding(&fixture, "rb-infra", "live.control.exchange",
                                "comments.extraction.control.queue", "[\"live.control.*\"]") &&
        cross_repo_seed_keyed_channel(&fixture, "rb-consumer", "comments.extraction.control.queue",
                                      "LISTENS_ON", "{\"transport\":\"rabbitmq\"}", "register",
                                      "worker.py");
    if (!setup) {
        cross_repo_fixture_end(&fixture);
        FAIL("failed to seed the consumer-side fixture");
    }
    const char *target = "rb-producer";
    cbm_cross_repo_result_t result = cbm_cross_repo_match("rb-consumer", &target, 1);
    int producer_edges = cross_repo_count_edges(&fixture, "rb-producer", "CROSS_CHANNEL");
    int consumer_edges = cross_repo_count_edges(&fixture, "rb-consumer", "CROSS_CHANNEL");
    cross_repo_fixture_end(&fixture);
    ASSERT_FALSE(result.failed);
    ASSERT_EQ(result.channel_edges, 1);
    ASSERT_EQ(producer_edges, 1);
    ASSERT_EQ(consumer_edges, 1);
    PASS();
}

TEST(cross_channel_amqp_wildcards_match_words_not_strings) {
    ASSERT_TRUE(cbm_cross_repo_amqp_key_matches("processed.*", "processed.sentiments"));
    ASSERT_FALSE(cbm_cross_repo_amqp_key_matches("processed.*", "processed.a.b"));
    ASSERT_FALSE(cbm_cross_repo_amqp_key_matches("processed.*", "processed"));
    ASSERT_TRUE(cbm_cross_repo_amqp_key_matches("live.control.*", "live.control.start"));
    ASSERT_FALSE(cbm_cross_repo_amqp_key_matches("live.control.*", "live.controls.start"));
    ASSERT_TRUE(cbm_cross_repo_amqp_key_matches("#", "anything.at.all"));
    ASSERT_TRUE(cbm_cross_repo_amqp_key_matches("#", ""));
    ASSERT_TRUE(cbm_cross_repo_amqp_key_matches("a.#", "a"));
    ASSERT_TRUE(cbm_cross_repo_amqp_key_matches("a.#", "a.b.c"));
    ASSERT_TRUE(cbm_cross_repo_amqp_key_matches("a.#.z", "a.z"));
    ASSERT_TRUE(cbm_cross_repo_amqp_key_matches("a.#.z", "a.b.c.z"));
    ASSERT_FALSE(cbm_cross_repo_amqp_key_matches("a.#.z", "a.b.c"));
    ASSERT_TRUE(cbm_cross_repo_amqp_key_matches("*.*.z", "a.b.z"));
    ASSERT_FALSE(cbm_cross_repo_amqp_key_matches("*.*.z", "a.z"));
    ASSERT_TRUE(cbm_cross_repo_amqp_key_matches("comments.processed", "comments.processed"));
    ASSERT_FALSE(cbm_cross_repo_amqp_key_matches("comments.processed", "comments.processed.x"));
    ASSERT_FALSE(cbm_cross_repo_amqp_key_matches("comments.processe", "comments.processed"));
    PASS();
}

TEST(cross_channel_wildcard_binding_resolves_and_many_keys_yield_one_edge_per_site) {
    cross_repo_fixture_t fixture;
    bool setup =
        cross_repo_fixture_begin(&fixture) &&
        cross_repo_seed_keyed_channel(&fixture, "rb-producer", "workers.processed.exchange",
                                      "EMITS",
                                      "{\"transport\":\"rabbitmq\","
                                      "\"routing_keys\":[\"processed.sentiments\"]}",
                                      "publish_sentiments", "sentiment.py") &&
        cross_repo_seed_binding(&fixture, "rb-infra", "workers.processed.exchange",
                                "all-processed.queue", "[\"processed.*\"]") &&
        cross_repo_seed_keyed_channel(&fixture, "rb-consumer", "all-processed.queue", "LISTENS_ON",
                                      "{\"transport\":\"rabbitmq\"}", "consume_all", "all.js") &&
        cross_repo_seed_keyed_channel(
            &fixture, "rb-producer", "notifications.insights.exchange", "EMITS",
            "{\"transport\":\"rabbitmq\",\"routing_keys\":[\"notifications.trending_topics\","
            "\"notifications.sentiment_analysis\",\"notifications.highlight_comments\","
            "\"notifications.people_requests\",\"notifications.questions\","
            "\"notifications.competitors\",\"notifications.sponsors\",\"notifications.hashtags\","
            "\"notifications.mini_trendings\",\"notifications.crisis_alert\"]}",
            "notify", "notify.py") &&
        cross_repo_seed_binding(
            &fixture, "rb-infra", "notifications.insights.exchange", "notifications.insights.queue",
            "[\"notifications.trending_topics\",\"notifications.sentiment_analysis\","
            "\"notifications.highlight_comments\",\"notifications.people_requests\","
            "\"notifications.questions\",\"notifications.competitors\","
            "\"notifications.sponsors\",\"notifications.hashtags\","
            "\"notifications.mini_trendings\",\"notifications.crisis_alert\"]") &&
        cross_repo_seed_keyed_channel(&fixture, "rb-consumer", "notifications.insights.queue",
                                      "LISTENS_ON", "{\"transport\":\"rabbitmq\"}",
                                      "consume_notifications", "notifications.js");
    if (!setup) {
        cross_repo_fixture_end(&fixture);
        FAIL("failed to seed the wildcard fixture");
    }
    const char *target = "rb-consumer";
    cbm_cross_repo_result_t result = cbm_cross_repo_match("rb-producer", &target, 1);
    int producer_edges = cross_repo_count_edges(&fixture, "rb-producer", "CROSS_CHANNEL");
    int consumer_edges = cross_repo_count_edges(&fixture, "rb-consumer", "CROSS_CHANNEL");
    bool wildcard_resolved =
        cross_repo_edge_props_have(&fixture, "rb-producer", "CROSS_CHANNEL",
                                   "\"channel_name\":\"all-processed.queue\"") &&
        cross_repo_edge_props_have(&fixture, "rb-producer", "CROSS_CHANNEL",
                                   "\"routing_key\":\"processed.sentiments\"");
    bool notifications_resolved =
        cross_repo_edge_props_have(&fixture, "rb-producer", "CROSS_CHANNEL",
                                   "\"channel_name\":\"notifications.insights.queue\"");
    cross_repo_fixture_end(&fixture);
    ASSERT_FALSE(result.failed);
    ASSERT_EQ(result.channel_edges, 2);
    ASSERT_EQ(producer_edges, 2);
    ASSERT_EQ(consumer_edges, 2);
    ASSERT_TRUE(wildcard_resolved);
    ASSERT_TRUE(notifications_resolved);
    PASS();
}

TEST(cross_channel_key_without_binding_produces_no_edge) {
    cross_repo_fixture_t fixture;
    bool setup =
        cross_repo_fixture_begin(&fixture) &&
        /* Key bound on ANOTHER exchange: the exchange is named, so it scopes. */
        cross_repo_seed_keyed_channel(&fixture, "rb-producer", "comments.processed.exchange",
                                      "EMITS",
                                      "{\"transport\":\"rabbitmq\","
                                      "\"routing_keys\":[\"processed.sentiments\"]}",
                                      "publish_wrong_exchange", "a.py") &&
        /* Key bound nowhere. */
        cross_repo_seed_keyed_channel(&fixture, "rb-producer", "workers.processed.exchange",
                                      "EMITS",
                                      "{\"transport\":\"rabbitmq\","
                                      "\"routing_keys\":[\"nobody.listens\"]}",
                                      "publish_unbound_key", "b.py") &&
        /* Exchange with no bindings at all. */
        cross_repo_seed_keyed_channel(&fixture, "rb-producer", "egress.exchange", "EMITS",
                                      "{\"transport\":\"rabbitmq\","
                                      "\"routing_keys\":[\"content.publish.requested\"]}",
                                      "publish_unbound_exchange", "c.py") &&
        cross_repo_seed_binding(&fixture, "rb-infra", "workers.processed.exchange",
                                "all-processed.queue", "[\"processed.*\"]") &&
        cross_repo_seed_keyed_channel(&fixture, "rb-consumer", "all-processed.queue", "LISTENS_ON",
                                      "{\"transport\":\"rabbitmq\"}", "consume_all", "all.js") &&
        cross_repo_seed_keyed_channel(&fixture, "rb-consumer", "egress.publish.queue", "LISTENS_ON",
                                      "{\"transport\":\"rabbitmq\"}", "consume_egress",
                                      "egress.js");
    if (!setup) {
        cross_repo_fixture_end(&fixture);
        FAIL("failed to seed the negative fixture");
    }
    const char *target = "rb-consumer";
    cbm_cross_repo_result_t result = cbm_cross_repo_match("rb-producer", &target, 1);
    int producer_edges = cross_repo_count_edges(&fixture, "rb-producer", "CROSS_CHANNEL");
    int consumer_edges = cross_repo_count_edges(&fixture, "rb-consumer", "CROSS_CHANNEL");
    cross_repo_fixture_end(&fixture);
    ASSERT_FALSE(result.failed);
    ASSERT_EQ(result.channel_edges, 0);
    ASSERT_EQ(producer_edges, 0);
    ASSERT_EQ(consumer_edges, 0);
    PASS();
}

TEST(cross_channel_test_file_listener_does_not_shadow_the_real_one) {
    cross_repo_fixture_t fixture;
    bool setup =
        cross_repo_fixture_begin(&fixture) &&
        cross_repo_seed_keyed_channel(&fixture, "rb-producer", "comments.extraction.control.queue",
                                      "EMITS", "{\"transport\":\"rabbitmq\"}", "send_control",
                                      "rabbitmq.js") &&
        /* Seeded first, so it is the row a LIMIT 1 lookup returns. */
        cross_repo_seed_keyed_channel(&fixture, "rb-consumer", "comments.extraction.control.queue",
                                      "LISTENS_ON", "{\"transport\":\"rabbitmq\"}",
                                      "test_reconnect",
                                      "shared/tests/test_rabbitmq_reconnect.py") &&
        cross_repo_seed_keyed_channel(&fixture, "rb-consumer", "comments.extraction.control.queue",
                                      "LISTENS_ON", "{\"transport\":\"rabbitmq\"}", "register",
                                      "shared/worker/abstract_worker.py");
    if (!setup) {
        cross_repo_fixture_end(&fixture);
        FAIL("failed to seed the shadowed listener fixture");
    }
    const char *target = "rb-consumer";
    cbm_cross_repo_result_t result = cbm_cross_repo_match("rb-producer", &target, 1);
    int producer_edges = cross_repo_count_edges(&fixture, "rb-producer", "CROSS_CHANNEL");
    bool real_listener = cross_repo_edge_props_have(&fixture, "rb-producer", "CROSS_CHANNEL",
                                                    "\"target_function\":\"register\"");
    cross_repo_fixture_end(&fixture);
    ASSERT_FALSE(result.failed);
    ASSERT_EQ(producer_edges, 1);
    ASSERT_TRUE(real_listener);
    PASS();
}

SUITE(cross_repo) {
    RUN_TEST(cross_repo_ignores_http_call_declared_in_a_test_file);
    RUN_TEST(cross_repo_ignores_route_declared_in_a_test_file);
    RUN_TEST(cross_channel_ignores_emitter_in_a_test_file);
    RUN_TEST(cross_channel_ignores_listener_in_a_test_file);
    RUN_TEST(cross_repo_accepts_project_with_missed_shadow_row_issue1609);
    RUN_TEST(cross_repo_null_target_fails_without_dereference);
    RUN_TEST(cross_repo_wildcard_keeps_projects_containing_internal_tokens);
    RUN_TEST(cross_repo_scan_bound_counts_examined_rows_not_matches);
    RUN_TEST(cross_repo_propagates_delete_failure);
    RUN_TEST(cross_repo_failed_bidirectional_insert_is_not_counted);
    RUN_TEST(cross_repo_cancel_mid_run_keeps_completed_target_and_stops_before_later_target);
    RUN_TEST(cross_repo_pre_cancel_preserves_existing_cross_edges);
    RUN_TEST(cross_channel_same_name_and_transport_links);
    RUN_TEST(cross_channel_same_name_different_transport_does_not_link);
    RUN_TEST(cross_channel_ignores_transport_lifecycle_events);
    RUN_TEST(cross_channel_resolves_exchange_and_key_through_binding_in_a_third_project);
    RUN_TEST(cross_channel_consumer_side_run_resolves_the_binding_too);
    RUN_TEST(cross_channel_amqp_wildcards_match_words_not_strings);
    RUN_TEST(cross_channel_wildcard_binding_resolves_and_many_keys_yield_one_edge_per_site);
    RUN_TEST(cross_channel_key_without_binding_produces_no_edge);
    RUN_TEST(cross_channel_test_file_listener_does_not_shadow_the_real_one);
    RUN_TEST(cross_channel_listener_side_run_keeps_its_edges);
}
