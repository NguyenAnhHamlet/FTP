#ifndef __TRIE__
#define __TRIE__

#include <stdbool.h>

typedef struct trie_node
{
    struct trie_node* child_node[26];
    bool word_end;

} trie_node;

trie_node* init_node();
trie_node* insert_key(trie_node* root, char* key, int len);
bool search_key(trie_node* root, char* key, int len);

#endif