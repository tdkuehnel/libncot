#include "node.h"
#include "log.h"

struct ncot_node *ncot_node_new()
{
  struct ncot_node *node;
  node = calloc(1, sizeof(struct ncot_node));
  return node;
}

void ncot_node_init(struct ncot_node *node) {
  if (node) {
    uuid_create(&node->uuid);
    uuid_make(node->uuid, UUID_MAKE_V1);    
  } else {
    NCOT_LOG_WARNING("Invalid node passed to ncot_node_init\n");
  }
}

void ncot_node_free(struct ncot_node **pnode) {
  struct ncot_node *node;
  if (pnode) {
    node = *pnode;
    if (node) {
      if (node->uuid) uuid_destroy(node->uuid);
      free(node);
      *pnode = NULL;
    } else
      NCOT_LOG_ERROR("Invalid ncot_node\n");
  } else 
    NCOT_LOG_ERROR("Invalid argument (*node)\n");
}

