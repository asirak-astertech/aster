/* Offline publish/subscribe with Aster's stable C application ABI. */

#include "aster_mesh.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static aster_bytes_t bytes(const void *data, size_t len) {
    return (aster_bytes_t){.data = data, .len = len};
}

static void require_ok(const char *operation, aster_status_t status) {
    if (status == ASTER_OK) {
        return;
    }

    /* Diagnostics are thread-local, sanitized strings owned by the library. */
    aster_owned_buffer_t error = ASTER_STRUCT_INIT(aster_owned_buffer_t);
    if (aster_last_error(&error) == ASTER_OK) {
        fprintf(stderr, "%s failed (%u): %.*s\n", operation, status,
                (int)error.len, error.data == NULL ? "" : (char *)error.data);
        aster_buffer_free(&error);
    } else {
        fprintf(stderr, "%s failed (%u)\n", operation, status);
    }
    exit(EXIT_FAILURE);
}

static uint8_t *read_file(const char *path, size_t *length) {
    FILE *file = fopen(path, "rb");
    if (file == NULL) {
        perror(path);
        exit(EXIT_FAILURE);
    }
    if (fseek(file, 0, SEEK_END) != 0) {
        perror("fseek");
        exit(EXIT_FAILURE);
    }
    long size = ftell(file);
    if (size <= 0 || fseek(file, 0, SEEK_SET) != 0) {
        fprintf(stderr, "%s is empty or unreadable\n", path);
        exit(EXIT_FAILURE);
    }
    uint8_t *contents = malloc((size_t)size);
    if (contents == NULL || fread(contents, 1, (size_t)size, file) != (size_t)size) {
        fprintf(stderr, "could not read %s\n", path);
        exit(EXIT_FAILURE);
    }
    fclose(file);
    *length = (size_t)size;
    return contents;
}

int main(int argc, char **argv) {
    int exit_code = EXIT_SUCCESS;

    if (argc != 3) {
        fprintf(stderr, "usage: %s PROVISIONING_BUNDLE DATABASE\n", argv[0]);
        return EXIT_FAILURE;
    }

    size_t bundle_len = 0;
    uint8_t *bundle = read_file(argv[1], &bundle_len);

    /* Initialize every versioned structure before setting its fields. */
    aster_node_options_t options = ASTER_STRUCT_INIT(aster_node_options_t);
    require_ok("initialize node options", aster_node_options_init(&options));
    options.store_path = bytes(argv[2], strlen(argv[2]));
    options.provisioning_bundle = bytes(bundle, bundle_len);

    aster_node_t node = {0};
    require_ok("open node", aster_node_open(&options, &node));

    const char topic[] = "position.current";
    const char scope[] = "mission/team/alpha";
    const char logical_key[] = "unit-7";
    const char payload[] = "{\"lat\":38.9,\"lon\":-77.0}";

    /* Subscribe first so local and remote items use the same durable,
     * at-least-once delivery path. */
    aster_subscribe_request_t subscribe = ASTER_STRUCT_INIT(aster_subscribe_request_t);
    subscribe.topic = bytes(topic, sizeof(topic) - 1);
    subscribe.scope = bytes(scope, sizeof(scope) - 1);
    subscribe.data_class = ASTER_DATA_CLASS_ANY;

    uint64_t subscription = 0;
    require_ok("subscribe", aster_node_subscribe(node, &subscribe, &subscription));

    /* Publish needs no peer. ASTER_OK means the item is durably committed
     * locally; it does not promise remote delivery. */
    aster_publish_request_t publish = ASTER_STRUCT_INIT(aster_publish_request_t);
    publish.data_class = ASTER_STATE;
    publish.priority = ASTER_IMMEDIATE;
    publish.topic = bytes(topic, sizeof(topic) - 1);
    publish.scope = bytes(scope, sizeof(scope) - 1);
    publish.logical_key = bytes(logical_key, sizeof(logical_key) - 1);
    publish.payload = bytes(payload, sizeof(payload) - 1);
    publish.has_ttl = 1;
    publish.ttl_ms = 60000; /* Expiry is independent of priority. */

    aster_publish_receipt_t receipt = ASTER_STRUCT_INIT(aster_publish_receipt_t);
    require_ok("publish", aster_node_publish(node, &publish, &receipt));

    aster_poll_request_t poll = ASTER_STRUCT_INIT(aster_poll_request_t);
    poll.subscription = subscription;
    poll.limit = 1;
    aster_deliveries_t deliveries = {0};
    require_ok("poll", aster_node_poll(node, &poll, &deliveries));

    size_t delivery_count = 0;
    require_ok("count deliveries", aster_deliveries_len(deliveries, &delivery_count));
    if (delivery_count == 0) {
        fprintf(stderr, "the local publication was not delivered\n");
        exit_code = EXIT_FAILURE;
        goto cleanup_deliveries;
    }

    aster_delivery_t delivery = ASTER_STRUCT_INIT(aster_delivery_t);
    require_ok("get delivery", aster_deliveries_get(deliveries, 0, &delivery));
    require_ok("close delivery page", aster_deliveries_close(&deliveries));

    printf("item=");
    for (size_t index = 0; index < ASTER_ID_BYTES; ++index) {
        printf("%02x", receipt.item_id[index]);
    }
    printf(" payload=%.*s\n", (int)delivery.item.payload.len,
           delivery.item.payload.data == NULL ? "" : (char *)delivery.item.payload.data);

    /* Acknowledge only after application processing succeeds. */
    aster_ack_request_t ack = ASTER_STRUCT_INIT(aster_ack_request_t);
    ack.subscription = subscription;
    memcpy(ack.item_id, delivery.item.item_id, ASTER_ID_BYTES);
    require_ok("acknowledge", aster_node_acknowledge(node, &ack));

    require_ok("free delivery", aster_delivery_free(&delivery));
    goto cleanup_node;

cleanup_deliveries:
    require_ok("close delivery page", aster_deliveries_close(&deliveries));
cleanup_node:
    require_ok("close node", aster_node_close(&node));
    free(bundle);
    return exit_code;
}
